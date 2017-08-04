package net.corda.core.transactions

import co.paralleluniverse.strands.Strand
import net.corda.core.contracts.*
import net.corda.core.crypto.*
import net.corda.core.identity.Party
import net.corda.core.internal.FlowStateMachine
import net.corda.core.node.ServiceHub
import java.security.KeyPair
import java.security.PublicKey
import java.security.SignatureException
import java.time.Duration
import java.time.Instant
import java.util.*

/**
 * A TransactionBuilder is a transaction class that's mutable (unlike the others which are all immutable). It is
 * intended to be passed around contracts that may edit it by adding new states/commands. Then once the states
 * and commands are right, this class can be used as a holding bucket to gather signatures from multiple parties.
 *
 * The builder can be customised for specific transaction types, e.g. where additional processing is needed
 * before adding a state/command.
 *
 * @param notary Notary used for the transaction. If null, this indicates the transaction DOES NOT have a notary.
 * When this is set to a non-null value, an output state can be added by just passing in a [ContractState] – a
 * [TransactionState] with this notary specified will be generated automatically.
 */
open class TransactionBuilder(
        var notary: Party? = null,
        var lockId: UUID = (Strand.currentStrand() as? FlowStateMachine<*>)?.id?.uuid ?: UUID.randomUUID(),
        protected val inputs: MutableList<StateRef> = arrayListOf(),
        protected val attachments: MutableList<SecureHash> = arrayListOf(),
        protected val outputs: MutableList<TransactionState<ContractState>> = arrayListOf(),
        protected val commands: MutableList<Command<*>> = arrayListOf(),
        protected var window: TimeWindow? = null,
        protected var privacySalt: PrivacySalt = PrivacySalt()
    ) {
    constructor(notary: Party) : this (notary, (Strand.currentStrand() as? FlowStateMachine<*>)?.id?.uuid ?: UUID.randomUUID())

    /**
     * Creates a copy of the builder.
     */
    fun copy() = TransactionBuilder(
            notary = notary,
            inputs = ArrayList(inputs),
            attachments = ArrayList(attachments),
            outputs = ArrayList(outputs),
            commands = ArrayList(commands),
            window = window,
            privacySalt = privacySalt
    )

    // DOCSTART 1
    /** A more convenient way to add items to this transaction that calls the add* methods for you based on type */
    fun withItems(vararg items: Any): TransactionBuilder {
        for (t in items) {
            when (t) {
                is StateAndRef<*> -> addInputState(t)
                is SecureHash -> addAttachment(t)
                is TransactionState<*> -> addOutputState(t)
                is ContractState -> addOutputState(t)
                is Command<*> -> addCommand(t)
                is CommandData -> throw IllegalArgumentException("You passed an instance of CommandData, but that lacks the pubkey. You need to wrap it in a Command object first.")
                is TimeWindow -> setTimeWindow(t)
                is PrivacySalt -> setPrivacySalt(t)
                else -> throw IllegalArgumentException("Wrong argument type: ${t.javaClass}")
            }
        }
        return this
    }
    // DOCEND 1

    fun toWireTransaction() = WireTransaction(ArrayList(inputs), ArrayList(attachments),
            ArrayList(outputs), ArrayList(commands), notary, window, privacySalt)

    @Throws(AttachmentResolutionException::class, TransactionResolutionException::class)
    fun toLedgerTransaction(services: ServiceHub) = toWireTransaction().toLedgerTransaction(services)

    @Throws(AttachmentResolutionException::class, TransactionResolutionException::class, TransactionVerificationException::class)
    fun verify(services: ServiceHub) {
        toLedgerTransaction(services).verify()
    }

    open fun addInputState(stateAndRef: StateAndRef<*>): TransactionBuilder {
        val notary = stateAndRef.state.notary
        require(notary == this.notary) { "Input state requires notary \"$notary\" which does not match the transaction notary \"${this.notary}\"." }
        inputs.add(stateAndRef.ref)
        return this
    }

    fun addAttachment(attachmentId: SecureHash): TransactionBuilder {
        attachments.add(attachmentId)
        return this
    }

    fun addOutputState(state: TransactionState<*>): TransactionBuilder {
        outputs.add(state)
        return this
    }

    @JvmOverloads
    fun addOutputState(state: ContractState, notary: Party, encumbrance: Int? = null): TransactionBuilder {
        return addOutputState(TransactionState(state, notary, encumbrance))
    }

    /** A default notary must be specified during builder construction to use this method */
    fun addOutputState(state: ContractState): TransactionBuilder {
        checkNotNull(notary) { "Need to specify a notary for the state, or set a default one on TransactionBuilder initialisation" }
        addOutputState(state, notary!!)
        return this
    }

    fun addCommand(arg: Command<*>): TransactionBuilder {
        commands.add(arg)
        return this
    }

    fun addCommand(data: CommandData, vararg keys: PublicKey) = addCommand(Command(data, listOf(*keys)))
    fun addCommand(data: CommandData, keys: List<PublicKey>) = addCommand(Command(data, keys))

    /**
     * Sets the [TimeWindow] for this transaction, replacing the existing [TimeWindow] if there is one. To be valid, the
     * transaction must then be signed by the notary service within this window of time. In this way, the notary acts as
     * the Timestamp Authority.
     */
    fun setTimeWindow(timeWindow: TimeWindow): TransactionBuilder {
        check(notary != null) { "Only notarised transactions can have a time-window" }
        window = timeWindow
        return this
    }

    /**
     * The [TimeWindow] for the transaction can also be defined as [time] +/- [timeTolerance]. The tolerance should be
     * chosen such that your code can finish building the transaction and sending it to the Timestamp Authority within
     * that window of time, taking into account factors such as network latency. Transactions being built by a group of
     * collaborating parties may therefore require a higher time tolerance than a transaction being built by a single
     * node.
     */
    fun setTimeWindow(time: Instant, timeTolerance: Duration) = setTimeWindow(TimeWindow.withTolerance(time, timeTolerance))

    fun setPrivacySalt(privacySalt: PrivacySalt): TransactionBuilder {
        this.privacySalt = privacySalt
        return this
    }

    // Accessors that yield immutable snapshots.
    fun inputStates(): List<StateRef> = ArrayList(inputs)
    fun attachments(): List<SecureHash> = ArrayList(attachments)
    fun outputStates(): List<TransactionState<*>> = ArrayList(outputs)
    fun commands(): List<Command<*>> = ArrayList(commands)

    /** The signatures that have been collected so far - might be incomplete! */
    @Deprecated("Signatures should be gathered on a SignedTransaction instead.")
    protected val currentSigs = arrayListOf<TransactionSignature>()

    @Deprecated("Use ServiceHub.signInitialTransaction() instead.")
    fun signWith(key: KeyPair): TransactionBuilder {
        val signableData = SignableData(toWireTransaction().id, SignatureMetadata(1, Crypto.findSignatureScheme(key.public).schemeNumberID)) // A dummy platformVersion.
        addSignatureUnchecked(key.sign(signableData))
        return this
    }

    /** Adds the signature directly to the transaction, without checking it for validity. */
    @Deprecated("Use ServiceHub.signInitialTransaction() instead.")
    fun addSignatureUnchecked(sig: TransactionSignature): TransactionBuilder {
        currentSigs.add(sig)
        return this
    }

    @Deprecated("Use ServiceHub.signInitialTransaction() instead.")
    fun toSignedTransaction(checkSufficientSignatures: Boolean = true): SignedTransaction {
        if (checkSufficientSignatures) {
            val gotKeys = currentSigs.map { it.by }.toSet()
            val requiredKeys = commands.flatMap { it.signers }.toSet()
            val missing: Set<PublicKey> = requiredKeys.filter { !it.isFulfilledBy(gotKeys) }.toSet()
            if (missing.isNotEmpty())
                throw IllegalStateException("Missing signatures on the transaction for the public keys: ${missing.joinToString()}")
        }
        val wtx = toWireTransaction()
        return SignedTransaction(wtx, ArrayList(currentSigs))
    }

    /**
     * Checks that the given signature matches one of the commands and that it is a correct signature over the tx, then
     * adds it.
     *
     * @throws SignatureException if the signature didn't match the transaction contents.
     * @throws IllegalArgumentException if the signature key doesn't appear in any command.
     */
    @Deprecated("Use WireTransaction.checkSignature() instead.")
    fun checkAndAddSignature(sig: TransactionSignature) {
        checkSignature(sig)
        addSignatureUnchecked(sig)
    }

    /**
     * Checks that the given signature matches one of the commands and that it is a correct signature over the tx.
     *
     * @throws SignatureException if the signature didn't match the transaction contents.
     * @throws IllegalArgumentException if the signature key doesn't appear in any command.
     */
    @Deprecated("Use WireTransaction.checkSignature() instead.")
    fun checkSignature(sig: TransactionSignature) {
        require(commands.any { it.signers.any { sig.by in it.keys } }) { "Signature key doesn't match any command" }
        sig.verify(toWireTransaction().id)
    }
}