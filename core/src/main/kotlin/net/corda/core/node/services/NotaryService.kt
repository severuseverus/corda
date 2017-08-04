package net.corda.core.node.services

import net.corda.core.contracts.StateRef
import net.corda.core.contracts.TimeWindow
import net.corda.core.crypto.*
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.NotaryError
import net.corda.core.flows.NotaryException
import net.corda.core.identity.Party
import net.corda.core.node.ServiceHub
import net.corda.core.serialization.SingletonSerializeAsToken
import net.corda.core.serialization.serialize
import net.corda.core.utilities.loggerFor
import org.slf4j.Logger

abstract class NotaryService : SingletonSerializeAsToken() {
    abstract val services: ServiceHub

    abstract fun start()
    abstract fun stop()

    /**
     * Produces a notary service flow which has the corresponding sends and receives as [NotaryFlow.Client].
     * The first parameter is the client [Party] making the request and the second is the platform version
     * of the client's node. Use this version parameter to provide backwards compatibility if the notary flow protocol
     * changes.
     */
    abstract fun createServiceFlow(otherParty: Party, platformVersion: Int): FlowLogic<Void?>
}

/**
 * A base notary service implementation that provides functionality for cases where a signature by a single member
 * of the cluster is sufficient for transaction notarisation. For example, a single-node or a Raft notary.
 */
abstract class TrustedAuthorityNotaryService : NotaryService() {
    protected open val log: Logger = loggerFor<TrustedAuthorityNotaryService>()

    // TODO: specify the valid time window in config, and convert TimeWindowChecker to a utility method
    protected abstract val timeWindowChecker: TimeWindowChecker
    protected abstract val uniquenessProvider: UniquenessProvider

    fun validateTimeWindow(t: TimeWindow?) {
        if (t != null && !timeWindowChecker.isValid(t))
            throw NotaryException(NotaryError.TimeWindowInvalid)
    }

    /**
     * A NotaryException is thrown if any of the states have been consumed by a different transaction. Note that
     * this method does not throw an exception when input states are present multiple times within the transaction.
     */
    fun commitInputStates(inputs: List<StateRef>, txId: SecureHash, caller: Party) {
        try {
            uniquenessProvider.commit(inputs, txId, caller)
        } catch (e: UniquenessException) {
            val conflicts = inputs.filterIndexed { i, stateRef ->
                val consumingTx = e.error.stateHistory[stateRef]
                consumingTx != null && consumingTx != UniquenessProvider.ConsumingTx(txId, i, caller)
            }
            if (conflicts.isNotEmpty()) {
                // TODO: Create a new UniquenessException that only contains the conflicts filtered above.
                log.warn("Notary conflicts for $txId: $conflicts")
                throw notaryException(txId, e)
            }
        }
    }

    private fun notaryException(txId: SecureHash, e: UniquenessException): NotaryException {
        val conflictData = e.error.serialize()
        val signedConflict = SignedData(conflictData, sign(conflictData.bytes))
        return NotaryException(NotaryError.Conflict(txId, signedConflict))
    }

    fun sign(bits: ByteArray): DigitalSignature.WithKey {
        return services.keyManagementService.sign(bits, services.notaryIdentityKey)
    }

    fun sign(txId: SecureHash): TransactionSignature {
        val signableData = SignableData(txId, SignatureMetadata(services.myInfo.platformVersion, Crypto.findSignatureScheme(services.notaryIdentityKey).schemeNumberID))
        return services.keyManagementService.sign(signableData, services.notaryIdentityKey)
    }
}