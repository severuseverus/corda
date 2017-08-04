package net.corda.node.services.events

import co.paralleluniverse.fibers.Suspendable
import com.google.common.util.concurrent.ListenableFuture
import net.corda.core.contracts.*
import net.corda.core.crypto.containsAny
import net.corda.core.flows.*
import net.corda.core.getOrThrow
import net.corda.core.identity.AbstractParty
import net.corda.core.identity.Party
import net.corda.core.node.services.ServiceInfo
import net.corda.core.node.services.VaultQueryService
import net.corda.core.node.services.queryBy
import net.corda.core.node.services.vault.DEFAULT_PAGE_NUM
import net.corda.core.node.services.vault.PageSpecification
import net.corda.core.node.services.vault.QueryCriteria.VaultQueryCriteria
import net.corda.core.node.services.vault.Sort
import net.corda.core.node.services.vault.SortAttribute
import net.corda.core.transactions.TransactionBuilder
import net.corda.testing.DUMMY_NOTARY
import net.corda.node.services.network.NetworkMapService
import net.corda.node.services.statemachine.StateMachineManager
import net.corda.node.services.transactions.ValidatingNotaryService
import net.corda.testing.contracts.DummyContract
import net.corda.testing.node.MockNetwork
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.PublicKey
import java.time.Instant
import java.util.concurrent.Future
import kotlin.test.assertEquals

class ScheduledFlowTests {
    companion object {
        val PAGE_SIZE = 20
    }
    lateinit var mockNet: MockNetwork
    lateinit var notaryNode: MockNetwork.MockNode
    lateinit var nodeA: MockNetwork.MockNode
    lateinit var nodeB: MockNetwork.MockNode

    data class ScheduledState(val creationTime: Instant,
                              val source: Party,
                              val destination: Party,
                              val processed: Boolean = false,
                              override val linearId: UniqueIdentifier = UniqueIdentifier(),
                              override val contract: Contract = DummyContract()) : SchedulableState, LinearState {
        override fun nextScheduledActivity(thisStateRef: StateRef, flowLogicRefFactory: FlowLogicRefFactory): ScheduledActivity? {
            if (!processed) {
                val logicRef = flowLogicRefFactory.create(ScheduledFlow::class.java, thisStateRef)
                return ScheduledActivity(logicRef, creationTime)
            } else {
                return null
            }
        }

        override val participants: List<AbstractParty> = listOf(source, destination)

        override fun isRelevant(ourKeys: Set<PublicKey>): Boolean {
            return participants.any { it.owningKey.containsAny(ourKeys) }
        }
    }

    class InsertInitialStateFlow(val destination: Party) : FlowLogic<Unit>() {
        @Suspendable
        override fun call() {
            val scheduledState = ScheduledState(serviceHub.clock.instant(),
                    serviceHub.myInfo.legalIdentity, destination)

            val notary = serviceHub.networkMapCache.getAnyNotary()
            val builder = TransactionBuilder(notary)
            builder.withItems(scheduledState)
            val tx = serviceHub.signInitialTransaction(builder)
            subFlow(FinalityFlow(tx, setOf(serviceHub.myInfo.legalIdentity)))
        }
    }

    @SchedulableFlow
    class ScheduledFlow(val stateRef: StateRef) : FlowLogic<Unit>() {
        @Suspendable
        override fun call() {
            val state = serviceHub.toStateAndRef<ScheduledState>(stateRef)
            val scheduledState = state.state.data
            // Only run flow over states originating on this node
            if (scheduledState.source != serviceHub.myInfo.legalIdentity) {
                return
            }
            require(!scheduledState.processed) { "State should not have been previously processed" }
            val notary = state.state.notary
            val newStateOutput = scheduledState.copy(processed = true)
            val builder = TransactionBuilder(notary)
            builder.withItems(state, newStateOutput)
            val tx = serviceHub.signInitialTransaction(builder)
            subFlow(FinalityFlow(tx, setOf(scheduledState.source, scheduledState.destination)))
        }
    }

    @Before
    fun setup() {
        mockNet = MockNetwork(threadPerNode = true)
        notaryNode = mockNet.createNode(
                legalName = DUMMY_NOTARY.name,
                advertisedServices = *arrayOf(ServiceInfo(NetworkMapService.type), ServiceInfo(ValidatingNotaryService.type)))
        nodeA = mockNet.createNode(notaryNode.network.myAddress, start = false)
        nodeB = mockNet.createNode(notaryNode.network.myAddress, start = false)
        mockNet.startNodes()
    }

    @After
    fun cleanUp() {
        mockNet.stopNodes()
    }

    @Test
    fun `create and run scheduled flow then wait for result`() {
        var countScheduledFlows = 0
        nodeA.smm.track().updates.subscribe {
            if (it is StateMachineManager.Change.Add) {
                val initiator = it.logic.stateMachine.flowInitiator
                if (initiator is FlowInitiator.Scheduled)
                    countScheduledFlows++
            }
        }
        nodeA.services.startFlow(InsertInitialStateFlow(nodeB.info.legalIdentity))
        mockNet.waitQuiescent()
        val stateFromA = nodeA.database.transaction {
            nodeA.services.vaultQueryService.queryBy<ScheduledState>().states.single()
        }
        val stateFromB = nodeB.database.transaction {
            nodeB.services.vaultQueryService.queryBy<ScheduledState>().states.single()
        }
        assertEquals(1, countScheduledFlows)
        assertEquals(stateFromA, stateFromB, "Must be same copy on both nodes")
        assertTrue("Must be processed", stateFromB.state.data.processed)
    }

    @Test
    fun `run a whole batch of scheduled flows`() {
        val N = 100
        val futures = mutableListOf<ListenableFuture<*>>()
        for (i in 0..N - 1) {
            futures.add(nodeA.services.startFlow(InsertInitialStateFlow(nodeB.info.legalIdentity)).resultFuture)
            futures.add(nodeB.services.startFlow(InsertInitialStateFlow(nodeA.info.legalIdentity)).resultFuture)
        }
        mockNet.waitQuiescent()
        futures.forEach { it.getOrThrow() }

        // Convert the states into maps to make error reporting easier
        val statesFromA: Map<StateRef, TransactionState<ScheduledState>> = nodeA.database.transaction {
            queryStatesWithPaging(nodeA.services.vaultQueryService)
        }.map { it -> Pair(it.ref, it.state) }.toMap()
        val statesFromB: Map<StateRef, TransactionState<ScheduledState>> = nodeB.database.transaction {
            queryStatesWithPaging(nodeB.services.vaultQueryService)
        }.map { it -> Pair(it.ref, it.state) }.toMap()
        assertEquals(2 * N, statesFromA.count(), "Expect all states to be present")
        statesFromA.keys.forEach { ref ->
            if (ref !in statesFromB.keys) {
                throw IllegalStateException("State $ref is only present on node A.")
            }
        }
        statesFromB.keys.forEach { ref ->
            if (ref !in statesFromA.keys) {
                throw IllegalStateException("State $ref is only present on node B.")
            }
        }
        assertEquals(statesFromA, statesFromB, "Expect identical data on both nodes")
        assertTrue("Expect all states have run the scheduled task", statesFromB.values.all { it.data.processed })
    }

    // Demonstrate Vault Query paging
    private fun queryStatesWithPaging(vaultQueryService: VaultQueryService): List<StateAndRef<ScheduledState>> {
        var pageNumber = DEFAULT_PAGE_NUM
        val states = mutableListOf<StateAndRef<ScheduledState>>()
        do {
            val pageSpec = PageSpecification(pageSize = PAGE_SIZE, pageNumber = pageNumber)
            val results = vaultQueryService.queryBy<ScheduledState>(VaultQueryCriteria(), pageSpec)
            states.addAll(results.states)
            pageNumber++
        } while ((pageSpec.pageSize * (pageNumber)) <= results.totalStatesAvailable)
        return states.toList()
    }
}
