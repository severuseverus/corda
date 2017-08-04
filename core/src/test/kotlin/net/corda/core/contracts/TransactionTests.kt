package net.corda.core.contracts

import net.corda.contracts.asset.DUMMY_CASH_ISSUER_KEY
import net.corda.core.crypto.*
import net.corda.core.crypto.composite.CompositeKey
import net.corda.core.identity.Party
import net.corda.core.transactions.LedgerTransaction
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.WireTransaction
import net.corda.testing.*
import net.corda.testing.contracts.DummyContract
import org.junit.Test
import java.security.KeyPair
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class TransactionTests : TestDependencyInjectionBase() {
    private fun makeSigned(wtx: WireTransaction, vararg keys: KeyPair, notarySig: Boolean = true): SignedTransaction {
        val keySigs = keys.map { it.sign(SignableData(wtx.id, SignatureMetadata(1, Crypto.findSignatureScheme(it.public).schemeNumberID))) }
        val sigs = if (notarySig) {
            keySigs + DUMMY_NOTARY_KEY.sign(SignableData(wtx.id, SignatureMetadata(1, Crypto.findSignatureScheme(DUMMY_NOTARY_KEY.public).schemeNumberID)))
        } else {
            keySigs
        }
        return SignedTransaction(wtx, sigs)
    }

    @Test
    fun `signed transaction missing signatures - CompositeKey`() {
        val ak = generateKeyPair()
        val bk = generateKeyPair()
        val ck = generateKeyPair()
        val apub = ak.public
        val bpub = bk.public
        val cpub = ck.public
        val c1 = CompositeKey.Builder().addKeys(apub, bpub).build(2)
        val compKey = CompositeKey.Builder().addKeys(c1, cpub).build(1)
        val wtx = WireTransaction(
                inputs = listOf(StateRef(SecureHash.randomSHA256(), 0)),
                attachments = emptyList(),
                outputs = emptyList(),
                commands = listOf(dummyCommand(compKey, DUMMY_KEY_1.public, DUMMY_KEY_2.public)),
                notary = DUMMY_NOTARY,
                timeWindow = null
        )
        assertEquals(
                setOf(compKey, DUMMY_KEY_2.public),
                assertFailsWith<SignedTransaction.SignaturesMissingException> { makeSigned(wtx, DUMMY_KEY_1).verifyRequiredSignatures() }.missing
        )

        assertEquals(
                setOf(compKey, DUMMY_KEY_2.public),
                assertFailsWith<SignedTransaction.SignaturesMissingException> { makeSigned(wtx, DUMMY_KEY_1, ak).verifyRequiredSignatures() }.missing
        )
        makeSigned(wtx, DUMMY_KEY_1, DUMMY_KEY_2, ak, bk).verifyRequiredSignatures()
        makeSigned(wtx, DUMMY_KEY_1, DUMMY_KEY_2, ck).verifyRequiredSignatures()
        makeSigned(wtx, DUMMY_KEY_1, DUMMY_KEY_2, ak, bk, ck).verifyRequiredSignatures()
        makeSigned(wtx, DUMMY_KEY_1, DUMMY_KEY_2, ak).verifySignaturesExcept(compKey)
        makeSigned(wtx, DUMMY_KEY_1, ak).verifySignaturesExcept(compKey, DUMMY_KEY_2.public) // Mixed allowed to be missing.
    }

    @Test
    fun `signed transaction missing signatures`() {
        val wtx = WireTransaction(
                inputs = listOf(StateRef(SecureHash.randomSHA256(), 0)),
                attachments = emptyList(),
                outputs = emptyList(),
                commands = listOf(dummyCommand(DUMMY_KEY_1.public, DUMMY_KEY_2.public)),
                notary = DUMMY_NOTARY,
                timeWindow = null
        )
        assertFailsWith<IllegalArgumentException> { makeSigned(wtx, notarySig = false).verifyRequiredSignatures() }

        assertEquals(
                setOf(DUMMY_KEY_1.public),
                assertFailsWith<SignedTransaction.SignaturesMissingException> { makeSigned(wtx, DUMMY_KEY_2).verifyRequiredSignatures() }.missing
        )
        assertEquals(
                setOf(DUMMY_KEY_2.public),
                assertFailsWith<SignedTransaction.SignaturesMissingException> { makeSigned(wtx, DUMMY_KEY_1).verifyRequiredSignatures() }.missing
        )
        assertEquals(
                setOf(DUMMY_KEY_2.public),
                assertFailsWith<SignedTransaction.SignaturesMissingException> { makeSigned(wtx, DUMMY_CASH_ISSUER_KEY).verifySignaturesExcept(DUMMY_KEY_1.public) }.missing
        )

        makeSigned(wtx, DUMMY_KEY_1).verifySignaturesExcept(DUMMY_KEY_2.public)
        makeSigned(wtx, DUMMY_KEY_2).verifySignaturesExcept(DUMMY_KEY_1.public)

        makeSigned(wtx, DUMMY_KEY_1, DUMMY_KEY_2).verifyRequiredSignatures()
    }

    @Test
    fun `transactions with no inputs can have any notary`() {
        val baseOutState = TransactionState(DummyContract.SingleOwnerState(0, ALICE), DUMMY_NOTARY)
        val inputs = emptyList<StateAndRef<*>>()
        val outputs = listOf(baseOutState, baseOutState.copy(notary = ALICE), baseOutState.copy(notary = BOB))
        val commands = emptyList<AuthenticatedObject<CommandData>>()
        val attachments = emptyList<Attachment>()
        val id = SecureHash.randomSHA256()
        val timeWindow: TimeWindow? = null
        val privacySalt: PrivacySalt = PrivacySalt()
        val transaction: LedgerTransaction = LedgerTransaction(
                inputs,
                outputs,
                commands,
                attachments,
                id,
                null,
                timeWindow,
                privacySalt
        )

        transaction.verify()
    }

    @Test
    fun `transaction cannot have duplicate inputs`() {
        val stateRef = StateRef(SecureHash.randomSHA256(), 0)
        fun buildTransaction() = WireTransaction(
                inputs = listOf(stateRef, stateRef),
                attachments = emptyList(),
                outputs = emptyList(),
                commands = listOf(dummyCommand(DUMMY_KEY_1.public, DUMMY_KEY_2.public)),
                notary = DUMMY_NOTARY,
                timeWindow = null
        )

        assertFailsWith<IllegalStateException> { buildTransaction() }
    }

    @Test
    fun `general transactions cannot change notary`() {
        val notary: Party = DUMMY_NOTARY
        val inState = TransactionState(DummyContract.SingleOwnerState(0, ALICE), notary)
        val outState = inState.copy(notary = ALICE)
        val inputs = listOf(StateAndRef(inState, StateRef(SecureHash.randomSHA256(), 0)))
        val outputs = listOf(outState)
        val commands = emptyList<AuthenticatedObject<CommandData>>()
        val attachments = emptyList<Attachment>()
        val id = SecureHash.randomSHA256()
        val timeWindow: TimeWindow? = null
        val privacySalt: PrivacySalt = PrivacySalt()
        fun buildTransaction() = LedgerTransaction(
                inputs,
                outputs,
                commands,
                attachments,
                id,
                notary,
                timeWindow,
                privacySalt
        )

        assertFailsWith<TransactionVerificationException.NotaryChangeInWrongTransactionType> { buildTransaction() }
    }

    @Test
    fun `transactions with identical contents must have different ids`() {
        val outputState = TransactionState(DummyContract.SingleOwnerState(0, ALICE), DUMMY_NOTARY)
        fun buildTransaction() = WireTransaction(
                inputs = emptyList(),
                attachments = emptyList(),
                outputs = listOf(outputState),
                commands = listOf(dummyCommand(DUMMY_KEY_1.public, DUMMY_KEY_2.public)),
                notary = null,
                timeWindow = null,
                privacySalt = PrivacySalt() // Randomly-generated – used for calculating the id
        )

        val issueTx1 = buildTransaction()
        val issueTx2 = buildTransaction()

        assertNotEquals(issueTx1.id, issueTx2.id)
    }
}
