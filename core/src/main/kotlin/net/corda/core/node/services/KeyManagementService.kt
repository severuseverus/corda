package net.corda.core.node.services

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.crypto.DigitalSignature
import net.corda.core.crypto.SignableData
import net.corda.core.crypto.TransactionSignature
import net.corda.core.identity.AnonymousPartyAndPath
import net.corda.core.identity.PartyAndCertificate
import java.security.PublicKey

/**
 * The KMS is responsible for storing and using private keys to sign things. An implementation of this may, for example,
 * call out to a hardware security module that enforces various auditing and frequency-of-use requirements.
 */
interface KeyManagementService {
    /**
     * Returns a snapshot of the current signing [PublicKey]s.
     * For each of these keys a [PrivateKey] is available, that can be used later for signing.
     */
    val keys: Set<PublicKey>

    /**
     * Generates a new random [KeyPair] and adds it to the internal key storage. Returns the public part of the pair.
     */
    @Suspendable
    fun freshKey(): PublicKey

    /**
     * Generates a new random [KeyPair], adds it to the internal key storage, then generates a corresponding
     * [X509Certificate] and adds it to the identity service.
     *
     * @param identity identity to generate a key and certificate for. Must be an identity this node has CA privileges for.
     * @param revocationEnabled whether to check revocation status of certificates in the certificate path.
     * @return X.509 certificate and path to the trust root.
     */
    @Suspendable
    fun freshKeyAndCert(identity: PartyAndCertificate, revocationEnabled: Boolean): AnonymousPartyAndPath

    /**
     * Filter some keys down to the set that this node owns (has private keys for).
     *
     * @param candidateKeys keys which this node may own.
     */
    fun filterMyKeys(candidateKeys: Iterable<PublicKey>): Iterable<PublicKey>

    /**
     * Using the provided signing [PublicKey] internally looks up the matching [PrivateKey] and signs the data.
     * @param bytes The data to sign over using the chosen key.
     * @param publicKey The [PublicKey] partner to an internally held [PrivateKey], either derived from the node's primary identity,
     * or previously generated via the [freshKey] method.
     * If the [PublicKey] is actually a [CompositeKey] the first leaf signing key hosted by the node is used.
     * @throws IllegalArgumentException if the input key is not a member of [keys].
     * TODO A full [KeyManagementService] implementation needs to record activity to the [AuditService] and to limit signing to
     * appropriately authorised contexts and initiating users.
     */
    @Suspendable
    fun sign(bytes: ByteArray, publicKey: PublicKey): DigitalSignature.WithKey

    /**
     * Using the provided signing [PublicKey] internally looks up the matching [PrivateKey] and signs the [SignableData].
     * @param signableData a wrapper over transaction id (merkle root) and signature metadata.
     * @param publicKey The [PublicKey] partner to an internally held [PrivateKey], either derived from the node's primary identity,
     * or previously generated via the [freshKey] method.
     * If the [PublicKey] is actually a [CompositeKey] the first leaf signing key hosted by the node is used.
     * @throws IllegalArgumentException if the input key is not a member of [keys].
     * TODO: A full [KeyManagementService] implementation needs to record activity to the Audit Service and to limit signing to
     *      appropriately authorised contexts and initiating users.
     */
    @Suspendable
    fun sign(signableData: SignableData, publicKey: PublicKey): TransactionSignature
}
