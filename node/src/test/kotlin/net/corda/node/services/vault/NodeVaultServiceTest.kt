package net.corda.node.services.vault

import co.paralleluniverse.fibers.Suspendable
import net.corda.contracts.asset.Cash
import net.corda.contracts.asset.DUMMY_CASH_ISSUER
import net.corda.contracts.asset.sumCash
import net.corda.contracts.getCashBalance
import net.corda.core.contracts.*
import net.corda.core.crypto.generateKeyPair
import net.corda.core.crypto.sign
import net.corda.core.identity.AbstractParty
import net.corda.core.identity.AnonymousParty
import net.corda.core.identity.Party
import net.corda.core.node.services.*
import net.corda.core.node.services.vault.QueryCriteria
import net.corda.core.node.services.vault.QueryCriteria.VaultQueryCriteria
import net.corda.core.transactions.NotaryChangeWireTransaction
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.NonEmptySet
import net.corda.core.utilities.OpaqueBytes
import net.corda.core.utilities.toNonEmptySet
import net.corda.node.services.database.HibernateConfiguration
import net.corda.node.services.schema.NodeSchemaService
import net.corda.node.utilities.CordaPersistence
import net.corda.node.utilities.configureDatabase
import net.corda.testing.*
import net.corda.testing.contracts.fillWithSomeTestCash
import net.corda.testing.node.MockServices
import net.corda.testing.node.makeTestDataSourceProperties
import net.corda.testing.node.makeTestDatabaseProperties
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.After
import org.junit.Before
import org.junit.Test
import rx.observers.TestSubscriber
import java.math.BigDecimal
import java.sql.Connection
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NodeVaultServiceTest : TestDependencyInjectionBase() {
    lateinit var services: MockServices
    val vaultSvc: VaultService get() = services.vaultService
    val vaultQuery: VaultQueryService get() = services.vaultQueryService
    lateinit var database: CordaPersistence

    @Before
    fun setUp() {
        LogHelper.setLevel(NodeVaultService::class)
        val dataSourceProps = makeTestDataSourceProperties()
        database = configureDatabase(dataSourceProps, makeTestDatabaseProperties())
        database.transaction {
            val hibernateConfig = HibernateConfiguration(NodeSchemaService(), makeTestDatabaseProperties())
            services = object : MockServices() {
                override val vaultService: VaultService = makeVaultService(dataSourceProps, hibernateConfig)

                override fun recordTransactions(txs: Iterable<SignedTransaction>) {
                    for (stx in txs) {
                        validatedTransactions.addTransaction(stx)
                    }
                    // Refactored to use notifyAll() as we have no other unit test for that method with multiple transactions.
                    vaultService.notifyAll(txs.map { it.tx })
                }
                override val vaultQueryService : VaultQueryService = HibernateVaultQueryImpl(hibernateConfig, vaultService.updatesPublisher)

                override fun jdbcSession(): Connection = database.createSession()
            }
        }
    }

    @After
    fun tearDown() {
        database.close()
        LogHelper.reset(NodeVaultService::class)
    }

    @Suspendable
    private fun VaultService.unconsumedCashStatesForSpending(amount: Amount<Currency>,
                                                             onlyFromIssuerParties: Set<AbstractParty>? = null,
                                                             notary: Party? = null,
                                                             lockId: UUID = UUID.randomUUID(),
                                                             withIssuerRefs: Set<OpaqueBytes>? = null): VaultService.StatesForSpendingResult<Cash.State, Currency> {

        val notaryName = if (notary != null) listOf(notary.name) else null
        var baseCriteria: QueryCriteria = QueryCriteria.VaultQueryCriteria(notaryName = notaryName)
        if (onlyFromIssuerParties != null || withIssuerRefs != null) {
            baseCriteria = baseCriteria.and(QueryCriteria.FungibleAssetQueryCriteria(
                    issuerPartyName = onlyFromIssuerParties?.toList(),
                    issuerRef = withIssuerRefs?.toList()))
        }

        return tryLockFungibleStatesForSpending(lockId, baseCriteria, amount, Cash.State::class.java)
    }


    @Test
    fun `states not local to instance`() {
        database.transaction {

            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 3, 3, Random(0L))

            val w1 = vaultQuery.queryBy<Cash.State>().states
            assertThat(w1).hasSize(3)

            val originalVault = vaultSvc
            val originalVaultQuery = vaultQuery
            val services2 = object : MockServices() {
                override val vaultService: VaultService get() = originalVault
                override fun recordTransactions(txs: Iterable<SignedTransaction>) {
                    for (stx in txs) {
                        validatedTransactions.addTransaction(stx)
                        vaultService.notify(stx.tx)
                    }
                }
                override val vaultQueryService : VaultQueryService get() = originalVaultQuery
            }

            val w2 = services2.vaultQueryService.queryBy<Cash.State>().states
            assertThat(w2).hasSize(3)
        }
    }

    @Test
    fun `states for refs`() {
        database.transaction {

            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 3, 3, Random(0L))

            val w1 = vaultQuery.queryBy<Cash.State>().states
            assertThat(w1).hasSize(3)

            val states = vaultQuery.queryBy<Cash.State>(VaultQueryCriteria(stateRefs = listOf(w1[1].ref, w1[2].ref))).states
            assertThat(states).hasSize(2)
        }
    }

    @Test
    fun `states soft locking reserve and release`() {
        database.transaction {

            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 3, 3, Random(0L))

            val unconsumedStates = vaultQuery.queryBy<Cash.State>().states
            assertThat(unconsumedStates).hasSize(3)

            val stateRefsToSoftLock = NonEmptySet.of(unconsumedStates[1].ref, unconsumedStates[2].ref)

            // soft lock two of the three states
            val softLockId = UUID.randomUUID()
            vaultSvc.softLockReserve(softLockId, stateRefsToSoftLock)

            // all softlocked states
            assertThat(vaultSvc.softLockedStates<Cash.State>()).hasSize(2)
            // my softlocked states
            assertThat(vaultSvc.softLockedStates<Cash.State>(softLockId)).hasSize(2)

            // excluding softlocked states
            val unlockedStates1 = vaultQuery.queryBy<Cash.State>(VaultQueryCriteria(includeSoftlockedStates = false)).states
            assertThat(unlockedStates1).hasSize(1)

            // soft lock release one of the states explicitly
            vaultSvc.softLockRelease(softLockId, NonEmptySet.of(unconsumedStates[1].ref))
            val unlockedStates2 = vaultQuery.queryBy<Cash.State>(VaultQueryCriteria(includeSoftlockedStates = false)).states
            assertThat(unlockedStates2).hasSize(2)

            // soft lock release the rest by id
            vaultSvc.softLockRelease(softLockId)
            val unlockedStates = vaultQuery.queryBy<Cash.State>(VaultQueryCriteria(includeSoftlockedStates = false)).states
            assertThat(unlockedStates).hasSize(3)

            // should be back to original states
            assertThat(unlockedStates).isEqualTo(unconsumedStates)
        }
    }

    @Test
    fun `soft locking attempt concurrent reserve`() {

        val backgroundExecutor = Executors.newFixedThreadPool(2)
        val countDown = CountDownLatch(2)

        val softLockId1 = UUID.randomUUID()
        val softLockId2 = UUID.randomUUID()

        val vaultStates =
                database.transaction {
                    assertEquals(0.DOLLARS, services.getCashBalance(USD))
                    services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 3, 3, Random(0L))
                }
        val stateRefsToSoftLock = (vaultStates.states.map { it.ref }).toNonEmptySet()
        println("State Refs:: $stateRefsToSoftLock")

        // 1st tx locks states
        backgroundExecutor.submit {
            try {
                database.transaction {
                    vaultSvc.softLockReserve(softLockId1, stateRefsToSoftLock)
                    assertThat(vaultSvc.softLockedStates<Cash.State>(softLockId1)).hasSize(3)
                }
                println("SOFT LOCK STATES #1 succeeded")
            } catch(e: Throwable) {
                println("SOFT LOCK STATES #1 failed")
            } finally {
                countDown.countDown()
            }
        }

        // 2nd tx attempts to lock same states
        backgroundExecutor.submit {
            try {
                Thread.sleep(100)   // let 1st thread soft lock them 1st
                database.transaction {
                    vaultSvc.softLockReserve(softLockId2, stateRefsToSoftLock)
                    assertThat(vaultSvc.softLockedStates<Cash.State>(softLockId2)).hasSize(3)
                }
                println("SOFT LOCK STATES #2 succeeded")
            } catch(e: Throwable) {
                println("SOFT LOCK STATES #2 failed")
            } finally {
                countDown.countDown()
            }
        }

        countDown.await()
        database.transaction {
            val lockStatesId1 = vaultSvc.softLockedStates<Cash.State>(softLockId1)
            println("SOFT LOCK #1 final states: $lockStatesId1")
            assertThat(lockStatesId1.size).isIn(0, 3)
            val lockStatesId2 = vaultSvc.softLockedStates<Cash.State>(softLockId2)
            println("SOFT LOCK #2 final states: $lockStatesId2")
            assertThat(lockStatesId2.size).isIn(0, 3)
        }
    }

    @Test
    fun `soft locking partial reserve states fails`() {

        val softLockId1 = UUID.randomUUID()
        val softLockId2 = UUID.randomUUID()

        val vaultStates =
                database.transaction {
                    assertEquals(0.DOLLARS, services.getCashBalance(USD))
                    services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 3, 3, Random(0L))
                }
        val stateRefsToSoftLock = vaultStates.states.map { it.ref }
        println("State Refs:: $stateRefsToSoftLock")

        // lock 1st state with LockId1
        database.transaction {
            vaultSvc.softLockReserve(softLockId1, NonEmptySet.of(stateRefsToSoftLock.first()))
            assertThat(vaultSvc.softLockedStates<Cash.State>(softLockId1)).hasSize(1)
        }

        // attempt to lock all 3 states with LockId2
        database.transaction {
            assertThatExceptionOfType(StatesNotAvailableException::class.java).isThrownBy(
                    { vaultSvc.softLockReserve(softLockId2, stateRefsToSoftLock.toNonEmptySet()) }
            ).withMessageContaining("only 2 rows available").withNoCause()
        }
    }

    @Test
    fun `attempt to lock states already soft locked by me`() {

        val softLockId1 = UUID.randomUUID()

        val vaultStates =
                database.transaction {
                    assertEquals(0.DOLLARS, services.getCashBalance(USD))
                    services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 3, 3, Random(0L))
                }
        val stateRefsToSoftLock = (vaultStates.states.map { it.ref }).toNonEmptySet()
        println("State Refs:: $stateRefsToSoftLock")

        // lock states with LockId1
        database.transaction {
            vaultSvc.softLockReserve(softLockId1, stateRefsToSoftLock)
            assertThat(vaultSvc.softLockedStates<Cash.State>(softLockId1)).hasSize(3)
        }

        // attempt to relock same states with LockId1
        database.transaction {
            vaultSvc.softLockReserve(softLockId1, stateRefsToSoftLock)
            assertThat(vaultSvc.softLockedStates<Cash.State>(softLockId1)).hasSize(3)
        }
    }

    @Test
    fun `lock additional states to some already soft locked by me`() {

        val softLockId1 = UUID.randomUUID()

        val vaultStates =
                database.transaction {
                    assertEquals(0.DOLLARS, services.getCashBalance(USD))
                    services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 3, 3, Random(0L))
                }
        val stateRefsToSoftLock = vaultStates.states.map { it.ref }
        println("State Refs:: $stateRefsToSoftLock")

        // lock states with LockId1
        database.transaction {
            vaultSvc.softLockReserve(softLockId1, NonEmptySet.of(stateRefsToSoftLock.first()))
            assertThat(vaultSvc.softLockedStates<Cash.State>(softLockId1)).hasSize(1)
        }

        // attempt to lock all states with LockId1 (including previously already locked one)
        database.transaction {
            vaultSvc.softLockReserve(softLockId1, stateRefsToSoftLock.toNonEmptySet())
            assertThat(vaultSvc.softLockedStates<Cash.State>(softLockId1)).hasSize(3)
        }
    }

    @Test
    fun `unconsumedStatesForSpending exact amount`() {
        database.transaction {

            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 1, 1, Random(0L))

            val unconsumedStates = vaultQuery.queryBy<Cash.State>().states
            assertThat(unconsumedStates).hasSize(1)

            val spendableStatesUSD = vaultSvc.unconsumedCashStatesForSpending(100.DOLLARS).states
            spendableStatesUSD.forEach(::println)
            assertThat(spendableStatesUSD).hasSize(1)
            assertThat(spendableStatesUSD[0].state.data.amount.quantity).isEqualTo(100L * 100)
            assertThat(vaultSvc.softLockedStates<Cash.State>()).hasSize(1)
        }
    }

    @Test
    fun `unconsumedStatesForSpending from two issuer parties`() {
        database.transaction {

            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 1, 1, Random(0L), issuedBy = (DUMMY_CASH_ISSUER))
            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 1, 1, Random(0L), issuedBy = (BOC.ref(1)), issuerKey = BOC_KEY)

            val spendableStatesUSD = vaultSvc.unconsumedCashStatesForSpending(200.DOLLARS,
                    onlyFromIssuerParties = setOf(DUMMY_CASH_ISSUER.party, BOC)).states
            spendableStatesUSD.forEach(::println)
            assertThat(spendableStatesUSD).hasSize(2)
            assertThat(spendableStatesUSD[0].state.data.amount.token.issuer).isIn(DUMMY_CASH_ISSUER, BOC.ref(1))
            assertThat(spendableStatesUSD[1].state.data.amount.token.issuer).isIn(DUMMY_CASH_ISSUER, BOC.ref(1))
            assertThat(spendableStatesUSD[0].state.data.amount.token.issuer).isNotEqualTo(spendableStatesUSD[1].state.data.amount.token.issuer)
        }
    }

    @Test
    fun `unconsumedStatesForSpending from specific issuer party and refs`() {
        database.transaction {

            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 1, 1, Random(0L), issuedBy = (DUMMY_CASH_ISSUER))
            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 1, 1, Random(0L), issuedBy = (BOC.ref(1)), issuerKey = BOC_KEY, ref = OpaqueBytes.of(1))
            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 1, 1, Random(0L), issuedBy = (BOC.ref(2)), issuerKey = BOC_KEY, ref = OpaqueBytes.of(2))
            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 1, 1, Random(0L), issuedBy = (BOC.ref(3)), issuerKey = BOC_KEY, ref = OpaqueBytes.of(3))

            val unconsumedStates = vaultQuery.queryBy<Cash.State>().states
            assertThat(unconsumedStates).hasSize(4)

            val spendableStatesUSD = vaultSvc.unconsumedCashStatesForSpending(200.DOLLARS,
                    onlyFromIssuerParties = setOf(BOC), withIssuerRefs = setOf(OpaqueBytes.of(1), OpaqueBytes.of(2))).states
            assertThat(spendableStatesUSD).hasSize(2)
            assertThat(spendableStatesUSD[0].state.data.amount.token.issuer.party).isEqualTo(BOC)
            assertThat(spendableStatesUSD[0].state.data.amount.token.issuer.reference).isIn(BOC.ref(1).reference, BOC.ref(2).reference)
            assertThat(spendableStatesUSD[1].state.data.amount.token.issuer.reference).isIn(BOC.ref(1).reference, BOC.ref(2).reference)
            assertThat(spendableStatesUSD[0].state.data.amount.token.issuer.reference).isNotEqualTo(spendableStatesUSD[1].state.data.amount.token.issuer.reference)
        }
    }

    @Test
    fun `unconsumedStatesForSpending insufficient amount`() {
        database.transaction {

            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 1, 1, Random(0L))

            val unconsumedStates = vaultQuery.queryBy<Cash.State>().states
            assertThat(unconsumedStates).hasSize(1)

            val spendableStatesUSD = vaultSvc.unconsumedCashStatesForSpending(110.DOLLARS).states
            spendableStatesUSD.forEach(::println)
            assertThat(spendableStatesUSD).hasSize(1)
            assertThat(vaultSvc.softLockedStates<Cash.State>()).hasSize(0)
        }
    }

    @Test
    fun `unconsumedStatesForSpending small amount`() {
        database.transaction {

            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 2, 2, Random(0L))

            val unconsumedStates = vaultQuery.queryBy<Cash.State>().states
            assertThat(unconsumedStates).hasSize(2)

            val spendableStatesUSD = vaultSvc.unconsumedCashStatesForSpending(1.DOLLARS).states
            spendableStatesUSD.forEach(::println)
            assertThat(spendableStatesUSD).hasSize(1)
            assertThat(spendableStatesUSD[0].state.data.amount.quantity).isGreaterThanOrEqualTo(100L)
            assertThat(vaultSvc.softLockedStates<Cash.State>()).hasSize(1)
        }
    }

    @Test
    fun `states soft locking query granularity`() {
        database.transaction {

            services.fillWithSomeTestCash(100.DOLLARS, DUMMY_NOTARY, 10, 10, Random(0L))
            services.fillWithSomeTestCash(100.POUNDS, DUMMY_NOTARY, 10, 10, Random(0L))
            services.fillWithSomeTestCash(100.SWISS_FRANCS, DUMMY_NOTARY, 10, 10, Random(0L))

            var unlockedStates = 30
            val allStates = vaultQuery.queryBy<Cash.State>().states
            assertThat(allStates).hasSize(unlockedStates)

            for (i in 1..5) {
                val lockId = UUID.randomUUID()
                val spendableStatesUSD = vaultSvc.unconsumedCashStatesForSpending(20.DOLLARS, lockId = lockId)
                spendableStatesUSD.states.forEach(::println)
                assertThat(spendableStatesUSD.states.size <= unlockedStates)
                unlockedStates -= spendableStatesUSD.states.size
                val lockedStates = vaultSvc.softLockedStates<Cash.State>(lockId)
                if (spendableStatesUSD.locked) {
                    assertEquals(spendableStatesUSD.states.size, lockedStates.size)
                    val lockedTotal = lockedStates.map { it.state.data }.sumCash()
                    assertThat(spendableStatesUSD.foundAmount.toDecimal() >= BigDecimal("20.00"))
                    assertThat(lockedTotal == spendableStatesUSD.foundAmount)
                }
            }

        }
    }

    @Test
    fun addNoteToTransaction() {
        val megaCorpServices = MockServices(MEGA_CORP_KEY)

        database.transaction {
            val freshKey = services.legalIdentityKey

            // Issue a txn to Send us some Money
            val usefulBuilder = TransactionBuilder(null).apply {
                Cash().generateIssue(this, 100.DOLLARS `issued by` MEGA_CORP.ref(1), AnonymousParty(freshKey), DUMMY_NOTARY)
            }
            val usefulTX = megaCorpServices.signInitialTransaction(usefulBuilder)

            services.recordTransactions(usefulTX)

            vaultSvc.addNoteToTransaction(usefulTX.id, "USD Sample Note 1")
            vaultSvc.addNoteToTransaction(usefulTX.id, "USD Sample Note 2")
            vaultSvc.addNoteToTransaction(usefulTX.id, "USD Sample Note 3")
            assertEquals(3, vaultSvc.getTransactionNotes(usefulTX.id).count())

            // Issue more Money (GBP)
            val anotherBuilder = TransactionBuilder(null).apply {
                Cash().generateIssue(this, 200.POUNDS `issued by` MEGA_CORP.ref(1), AnonymousParty(freshKey), DUMMY_NOTARY)
            }
            val anotherTX = megaCorpServices.signInitialTransaction(anotherBuilder)

            services.recordTransactions(anotherTX)

            vaultSvc.addNoteToTransaction(anotherTX.id, "GBP Sample Note 1")
            assertEquals(1, vaultSvc.getTransactionNotes(anotherTX.id).count())
        }
    }

    @Test
    fun `is ownable state relevant`() {
        val service = (services.vaultService as NodeVaultService)
        val amount = Amount(1000, Issued(BOC.ref(1), GBP))
        val wellKnownCash = Cash.State(amount, services.myInfo.legalIdentity)
        assertTrue { service.isRelevant(wellKnownCash, services.keyManagementService.keys) }

        val anonymousIdentity = services.keyManagementService.freshKeyAndCert(services.myInfo.legalIdentityAndCert, false)
        val anonymousCash = Cash.State(amount, anonymousIdentity.party)
        assertTrue { service.isRelevant(anonymousCash, services.keyManagementService.keys) }

        val thirdPartyIdentity = AnonymousParty(generateKeyPair().public)
        val thirdPartyCash = Cash.State(amount, thirdPartyIdentity)
        assertFalse { service.isRelevant(thirdPartyCash, services.keyManagementService.keys) }
    }

    // TODO: Unit test linear state relevancy checks

    @Test
    fun `correct updates are generated for general transactions`() {
        val service = (services.vaultService as NodeVaultService)
        val vaultSubscriber = TestSubscriber<Vault.Update<*>>().apply {
            service.updates.subscribe(this)
        }

        val anonymousIdentity = services.keyManagementService.freshKeyAndCert(services.myInfo.legalIdentityAndCert, false)
        val thirdPartyIdentity = AnonymousParty(generateKeyPair().public)
        val amount = Amount(1000, Issued(BOC.ref(1), GBP))

        // Issue then move some cash
        val issueTx = TransactionBuilder(services.myInfo.legalIdentity).apply {
            Cash().generateIssue(this,
                    amount, anonymousIdentity.party, services.myInfo.legalIdentity)
        }.toWireTransaction()
        val cashState = StateAndRef(issueTx.outputs.single(), StateRef(issueTx.id, 0))

        database.transaction { service.notify(issueTx) }
        val expectedIssueUpdate = Vault.Update(emptySet(), setOf(cashState), null)

        database.transaction {
            val moveTx = TransactionBuilder(services.myInfo.legalIdentity).apply {
                Cash.generateSpend(services, this, Amount(1000, GBP), thirdPartyIdentity)
            }.toWireTransaction()
            service.notify(moveTx)
        }
        val expectedMoveUpdate = Vault.Update(setOf(cashState), emptySet(), null)

        val observedUpdates = vaultSubscriber.onNextEvents
        assertEquals(observedUpdates, listOf(expectedIssueUpdate, expectedMoveUpdate))
    }

    @Test
    fun `correct updates are generated when changing notaries`() {
        val service = (services.vaultService as NodeVaultService)
        val notary = services.myInfo.legalIdentity

        val vaultSubscriber = TestSubscriber<Vault.Update<*>>().apply {
            service.updates.subscribe(this)
        }

        val anonymousIdentity = services.keyManagementService.freshKeyAndCert(services.myInfo.legalIdentityAndCert, false)
        val thirdPartyIdentity = AnonymousParty(generateKeyPair().public)
        val amount = Amount(1000, Issued(BOC.ref(1), GBP))

        // Issue some cash
        val issueTx = TransactionBuilder(notary).apply {
            Cash().generateIssue(this, amount, anonymousIdentity.party, notary)
        }.toWireTransaction()

        // We need to record the issue transaction so inputs can be resolved for the notary change transaction
        val signedIssueTx = SignedTransaction(issueTx, listOf(BOC_KEY.sign(issueTx.id)))
        services.validatedTransactions.addTransaction(signedIssueTx)

        val initialCashState = StateAndRef(issueTx.outputs.single(), StateRef(issueTx.id, 0))

        // Change notary
        val newNotary = DUMMY_NOTARY
        val changeNotaryTx = NotaryChangeWireTransaction(listOf(initialCashState.ref), issueTx.notary!!, newNotary)
        val cashStateWithNewNotary = StateAndRef(initialCashState.state.copy(notary = newNotary), StateRef(changeNotaryTx.id, 0))

        database.transaction {
            service.notifyAll(listOf(issueTx, changeNotaryTx))
        }

        // Move cash
        val moveTx = database.transaction {
            TransactionBuilder(newNotary).apply {
                Cash.generateSpend(services, this, Amount(1000, GBP), thirdPartyIdentity)
            }.toWireTransaction()
        }

        database.transaction {
            service.notify(moveTx)
        }

        val expectedIssueUpdate = Vault.Update(emptySet(), setOf(initialCashState), null)
        val expectedNotaryChangeUpdate = Vault.Update(setOf(initialCashState), setOf(cashStateWithNewNotary), null, Vault.UpdateType.NOTARY_CHANGE)
        val expectedMoveUpdate = Vault.Update(setOf(cashStateWithNewNotary), emptySet(), null)

        val observedUpdates = vaultSubscriber.onNextEvents
        assertEquals(observedUpdates, listOf(expectedIssueUpdate, expectedNotaryChangeUpdate, expectedMoveUpdate))
    }
}
