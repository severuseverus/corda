package net.corda.node.services.events

import com.google.common.util.concurrent.SettableFuture
import net.corda.core.internal.ThreadBox
import net.corda.core.contracts.SchedulableState
import net.corda.core.contracts.ScheduledActivity
import net.corda.core.contracts.ScheduledStateRef
import net.corda.core.contracts.StateRef
import net.corda.core.flows.FlowInitiator
import net.corda.core.flows.FlowLogic
import net.corda.core.serialization.SingletonSerializeAsToken
import net.corda.core.then
import net.corda.core.utilities.loggerFor
import net.corda.core.utilities.trace
import net.corda.node.services.api.SchedulerService
import net.corda.node.services.api.ServiceHubInternal
import net.corda.node.services.statemachine.FlowLogicRefFactoryImpl
import net.corda.node.utilities.*
import org.apache.activemq.artemis.utils.ReusableLatch
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.statements.InsertStatement
import java.time.Instant
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import javax.annotation.concurrent.ThreadSafe

/**
 * A first pass of a simple [SchedulerService] that works with [MutableClock]s for testing, demonstrations and simulations
 * that also encompasses the [net.corda.core.node.services.Vault] observer for processing transactions.
 *
 * This will observe transactions as they are stored and schedule and unschedule activities based on the States consumed
 * or produced.
 *
 * Currently does not provide any system state other than the ContractState so the expectation is that a transaction
 * is the outcome of the activity in order to schedule another activity.  Once we have implemented more persistence
 * in the nodes, maybe we can consider multiple activities and whether the activities have been completed or not,
 * but that starts to sound a lot like off-ledger state.
 *
 * @param services Core node services.
 * @param schedulerTimerExecutor The executor the scheduler blocks on waiting for the clock to advance to the next
 * activity.  Only replace this for unit testing purposes.  This is not the executor the [FlowLogic] is launched on.
 */
@ThreadSafe
class NodeSchedulerService(private val services: ServiceHubInternal,
                           private val schedulerTimerExecutor: Executor = Executors.newSingleThreadExecutor(),
                           private val unfinishedSchedules: ReusableLatch = ReusableLatch(),
                           private val serverThread: AffinityExecutor)
    : SchedulerService, SingletonSerializeAsToken() {

    companion object {
        private val log = loggerFor<NodeSchedulerService>()
    }

    private object Table : JDBCHashedTable("${NODE_DATABASE_PREFIX}scheduled_states") {
        val output = stateRef("transaction_id", "output_index")
        val scheduledAt = instant("scheduled_at")
    }

    // Variables inside InnerState are protected with a lock by the ThreadBox and aren't in scope unless you're
    // inside mutex.locked {} code block. So we can't forget to take the lock unless we accidentally leak a reference
    // to somewhere.
    private class InnerState {
        var scheduledStates = object : AbstractJDBCHashMap<StateRef, ScheduledStateRef, Table>(Table, loadOnInit = true) {
            override fun keyFromRow(row: ResultRow): StateRef = StateRef(row[table.output.txId], row[table.output.index])

            override fun valueFromRow(row: ResultRow): ScheduledStateRef {
                return ScheduledStateRef(StateRef(row[table.output.txId], row[table.output.index]), row[table.scheduledAt])
            }

            override fun addKeyToInsert(insert: InsertStatement, entry: Map.Entry<StateRef, ScheduledStateRef>, finalizables: MutableList<() -> Unit>) {
                insert[table.output.txId] = entry.key.txhash
                insert[table.output.index] = entry.key.index
            }

            override fun addValueToInsert(insert: InsertStatement, entry: Map.Entry<StateRef, ScheduledStateRef>, finalizables: MutableList<() -> Unit>) {
                insert[table.scheduledAt] = entry.value.scheduledAt
            }

        }
        var earliestState: ScheduledStateRef? = null
        var rescheduled: SettableFuture<Boolean>? = null

        internal fun recomputeEarliest() {
            earliestState = scheduledStates.values.sortedBy { it.scheduledAt }.firstOrNull()
        }
    }

    private val mutex = ThreadBox(InnerState())

    // We need the [StateMachineManager] to be constructed before this is called in case it schedules a flow.
    fun start() {
        mutex.locked {
            recomputeEarliest()
            rescheduleWakeUp()
        }
    }

    override fun scheduleStateActivity(action: ScheduledStateRef) {
        log.trace { "Schedule $action" }
        mutex.locked {
            if (scheduledStates.put(action.ref, action) == null) {
                unfinishedSchedules.countUp()
            }
            if (action.scheduledAt.isBefore(earliestState?.scheduledAt ?: Instant.MAX)) {
                // We are earliest
                earliestState = action
                rescheduleWakeUp()
            } else if (earliestState?.ref == action.ref && earliestState!!.scheduledAt != action.scheduledAt) {
                // We were earliest but might not be any more
                recomputeEarliest()
                rescheduleWakeUp()
            }
        }
    }

    override fun unscheduleStateActivity(ref: StateRef) {
        log.trace { "Unschedule $ref" }
        mutex.locked {
            val removedAction = scheduledStates.remove(ref)
            if (removedAction != null) {
                unfinishedSchedules.countDown()
                if (removedAction == earliestState) {
                    recomputeEarliest()
                    rescheduleWakeUp()
                }
            }
        }
    }

    /**
     * This method first cancels the [java.util.concurrent.Future] for any pending action so that the
     * [awaitWithDeadline] used below drops through without running the action.  We then create a new
     * [java.util.concurrent.Future] for the new action (so it too can be cancelled), and then await the arrival of the
     * scheduled time.  If we reach the scheduled time (the deadline) without the [java.util.concurrent.Future] being
     * cancelled then we run the scheduled action.  Finally we remove that action from the scheduled actions and
     * recompute the next scheduled action.
     */
    internal fun rescheduleWakeUp() {
        // Note, we already have the mutex but we need the scope again here
        val (scheduledState, ourRescheduledFuture) = mutex.alreadyLocked {
            rescheduled?.cancel(false)
            rescheduled = SettableFuture.create()
            Pair(earliestState, rescheduled!!)
        }
        if (scheduledState != null) {
            schedulerTimerExecutor.execute {
                log.trace { "Scheduling as next $scheduledState" }
                // This will block the scheduler single thread until the scheduled time (returns false) OR
                // the Future is cancelled due to rescheduling (returns true).
                if (!services.clock.awaitWithDeadline(scheduledState.scheduledAt, ourRescheduledFuture)) {
                    log.trace { "Invoking as next $scheduledState" }
                    onTimeReached(scheduledState)
                } else {
                    log.trace { "Rescheduled $scheduledState" }
                }
            }
        }
    }

    private fun onTimeReached(scheduledState: ScheduledStateRef) {
        serverThread.execute {
            services.database.transaction {
                val scheduledFlow = getScheduledFlow(scheduledState)
                if (scheduledFlow != null) {
                    val future = services.startFlow(scheduledFlow, FlowInitiator.Scheduled(scheduledState)).resultFuture
                    future.then {
                        unfinishedSchedules.countDown()
                    }
                }
            }
        }
    }

    private fun getScheduledFlow(scheduledState: ScheduledStateRef): FlowLogic<*>? {
        val scheduledActivity = getScheduledActivity(scheduledState)
        var scheduledFlow: FlowLogic<*>? = null
        mutex.locked {
            // need to remove us from those scheduled, but only if we are still next
            scheduledStates.compute(scheduledState.ref) { _, value ->
                if (value === scheduledState) {
                    if (scheduledActivity == null) {
                        log.info("Scheduled state $scheduledState has rescheduled to never.")
                        unfinishedSchedules.countDown()
                        null
                    } else if (scheduledActivity.scheduledAt.isAfter(services.clock.instant())) {
                        log.info("Scheduled state $scheduledState has rescheduled to ${scheduledActivity.scheduledAt}.")
                        ScheduledStateRef(scheduledState.ref, scheduledActivity.scheduledAt)
                    } else {
                        // TODO: FlowLogicRefFactory needs to sort out the class loader etc
                        val flowLogic = FlowLogicRefFactoryImpl.toFlowLogic(scheduledActivity.logicRef)
                        log.trace { "Scheduler starting FlowLogic $flowLogic" }
                        scheduledFlow = flowLogic
                        null
                    }
                } else {
                    value
                }
            }
            // and schedule the next one
            recomputeEarliest()
            rescheduleWakeUp()
        }
        return scheduledFlow
    }

    private fun getScheduledActivity(scheduledState: ScheduledStateRef): ScheduledActivity? {
        val txState = services.loadState(scheduledState.ref)
        val state = txState.data as SchedulableState
        return try {
            // This can throw as running contract code.
            state.nextScheduledActivity(scheduledState.ref, FlowLogicRefFactoryImpl)
        } catch (e: Exception) {
            log.error("Attempt to run scheduled state $scheduledState resulted in error.", e)
            null
        }
    }
}
