package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.os.RemoteException
import android.system.keystore2.IKeystoreOperation
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * KeyMint `ErrorCode` values surfaced to clients through `ServiceSpecificException`, mirroring
 * keystore2's behavior when `begin()` rejects an operation.
 *
 * See hardware/interfaces/security/keymint/aidl/.../ErrorCode.aidl.
 */
object KeyMintErrors {
    const val INCOMPATIBLE_BLOCK_MODE = -12
    const val INCOMPATIBLE_PURPOSE = -13
    const val INCOMPATIBLE_PADDING = -16
    const val INCOMPATIBLE_DIGEST = -17
    const val INCOMPATIBLE_MGF_DIGEST = -78
    const val UNSUPPORTED_MGF_DIGEST = -79

    /** keystore2 ResponseCode::SYSTEM_ERROR, used for unexpected software failures. */
    const val SYSTEM_ERROR = 3

    /**
     * android.security.KeyStore#KEY_PERMANENTLY_INVALIDATED: a key whose TAG_USAGE_COUNT_LIMIT has
     * been exhausted is reported as permanently invalidated to the client.
     */
    const val KEY_PERMANENTLY_INVALIDATED = 17
}

/** Thrown when an operation must be rejected exactly like KeyMint's `begin()` would reject it. */
class KeyMintOperationException(val errorCode: Int, message: String) : Exception(message)

// A sealed interface to represent the different cryptographic operations we can perform.
private sealed interface CryptoPrimitive {
    fun updateAad(aad: ByteArray?) {}

    fun update(data: ByteArray?): ByteArray?

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?

    fun abort()
}

// Helper object to map KeyMint constants to JCA algorithm strings.
private object JcaAlgorithmMapper {

    fun digestName(digest: Int): String? =
        when (digest) {
            Digest.MD5 -> "MD5"
            Digest.SHA1 -> "SHA1"
            Digest.SHA_2_224 -> "SHA224"
            Digest.SHA_2_256 -> "SHA256"
            Digest.SHA_2_384 -> "SHA384"
            Digest.SHA_2_512 -> "SHA512"
            else -> null
        }

    fun mgf1Spec(digest: Int): MGF1ParameterSpec? =
        when (digest) {
            Digest.SHA1 -> MGF1ParameterSpec.SHA1
            Digest.SHA_2_224 -> MGF1ParameterSpec.SHA224
            Digest.SHA_2_256 -> MGF1ParameterSpec.SHA256
            Digest.SHA_2_384 -> MGF1ParameterSpec.SHA384
            Digest.SHA_2_512 -> MGF1ParameterSpec.SHA512
            else -> null
        }

    fun signatureAlgorithm(params: KeyMintAttestation): String {
        val digest =
            params.digest.firstOrNull()?.let(::digestName)
                ?: if (params.algorithm == Algorithm.EC) "NONE" else "SHA256"
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.EC -> "ECDSA"
                Algorithm.RSA ->
                    return if (params.padding.firstOrNull() == PaddingMode.RSA_PSS) {
                        "${digest}withRSA/PSS"
                    } else {
                        "${digest}withRSA"
                    }
                else -> throw IllegalArgumentException("Unsupported signature algorithm: ${params.algorithm}")
            }
        return "${digest}with${keyAlgo}"
    }

    /** Configures PSS explicitly so the salt length matches the framework's default. */
    fun configureSigner(signature: Signature, params: KeyMintAttestation) {
        if (params.algorithm != Algorithm.RSA) return
        if (params.padding.firstOrNull() != PaddingMode.RSA_PSS) return
        val digest = params.digest.firstOrNull()
        if (digest == null || digestName(digest) == null) return
        val saltLen =
            when (digest) {
                Digest.MD5 -> 16
                Digest.SHA1 -> 20
                Digest.SHA_2_224 -> 28
                Digest.SHA_2_256 -> 32
                Digest.SHA_2_384 -> 48
                Digest.SHA_2_512 -> 64
                else -> return
            }
        val digestName = digestName(digest)!!
        signature.setParameter(
            PSSParameterSpec(digestName, "MGF1", MGF1ParameterSpec(digestName), saltLen, 1)
        )
    }
}

/**
 * Validates an operation against the key's authorizations, mirroring KeyMint's `begin()` checks so
 * that unauthorized uses (wrong digest, padding, block mode, purpose or MGF digest) are rejected
 * with the same error codes a hardware backend would return.
 */
private object AuthorizationChecker {

    fun check(keyParams: KeyMintAttestation, opParams: KeyMintAttestation) {
        val purpose = opParams.purpose.firstOrNull()
        if (purpose != null && keyParams.purpose.isNotEmpty() && purpose !in keyParams.purpose) {
            throw KeyMintOperationException(
                KeyMintErrors.INCOMPATIBLE_PURPOSE,
                "Purpose ${KeyMintParameterLogger.purposeNames[purpose] ?: purpose} not authorized for this key",
            )
        }

        val digest = opParams.digest.firstOrNull()
        if (digest != null && keyParams.digest.isNotEmpty() && digest !in keyParams.digest) {
            throw KeyMintOperationException(
                KeyMintErrors.INCOMPATIBLE_DIGEST,
                "Digest $digest not authorized for this key",
            )
        }

        val padding = opParams.padding.firstOrNull()
        if (padding != null && keyParams.padding.isNotEmpty() && padding !in keyParams.padding) {
            throw KeyMintOperationException(
                KeyMintErrors.INCOMPATIBLE_PADDING,
                "Padding $padding not authorized for this key",
            )
        }

        val blockMode = opParams.blockMode.firstOrNull()
        if (blockMode != null && keyParams.blockMode.isNotEmpty() && blockMode !in keyParams.blockMode) {
            throw KeyMintOperationException(
                KeyMintErrors.INCOMPATIBLE_BLOCK_MODE,
                "Block mode $blockMode not authorized for this key",
            )
        }

        // RSA-OAEP MGF digest checks, following the VTS RsaOaepMGFDigest* matrix.
        if (opParams.padding.contains(PaddingMode.RSA_OAEP)) {
            val opMgf = opParams.rsaOaepMgfDigest.firstOrNull()
            val keyMgf = keyParams.rsaOaepMgfDigest
            when {
                opMgf == Digest.NONE ->
                    throw KeyMintOperationException(
                        KeyMintErrors.UNSUPPORTED_MGF_DIGEST,
                        "MGF digest NONE is not supported",
                    )
                opMgf != null && keyMgf.isNotEmpty() && opMgf !in keyMgf ->
                    throw KeyMintOperationException(
                        KeyMintErrors.INCOMPATIBLE_MGF_DIGEST,
                        "MGF digest $opMgf not authorized for this key",
                    )
                // An omitted MGF digest means the SHA-1 default (KeyMint spec, Tag::RSA_OAEP_MGF_DIGEST).
                opMgf == null && keyMgf.isNotEmpty() && Digest.SHA1 !in keyMgf ->
                    throw KeyMintOperationException(
                        KeyMintErrors.INCOMPATIBLE_MGF_DIGEST,
                        "Default SHA-1 MGF digest not authorized for this key",
                    )
            }
        }
    }
}

// Concrete implementation for Signing.
private class Signer(privateKey: PrivateKey, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.signatureAlgorithm(params)).apply {
            JcaAlgorithmMapper.configureSigner(this, params)
            initSign(privateKey)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (data != null) update(data)
        return this.signature.sign()
    }

    override fun abort() {}
}

// Concrete implementation for Verification.
private class Verifier(publicKey: PublicKey, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.signatureAlgorithm(params)).apply {
            JcaAlgorithmMapper.configureSigner(this, params)
            initVerify(publicKey)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (signature == null) throw SignatureException("Signature to verify is null")
        if (!this.signature.verify(signature)) {
            // Throwing an exception is how Keystore signals verification failure.
            throw SignatureException("Signature verification failed")
        }
        // A successful verification returns no data.
        return null
    }

    override fun abort() {}
}

/** MAC primitive for HMAC keys (PURPOSE_SIGN/PURPOSE_VERIFY on symmetric keys). */
private class MacPrimitive(secretKey: SecretKey, params: KeyMintAttestation) : CryptoPrimitive {
    private val mac: Mac =
        Mac.getInstance(
            "Hmac${params.digest.firstOrNull()?.let(JcaAlgorithmMapper::digestName) ?: "SHA256"}"
        )
            .apply { init(secretKey) }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        return mac.doFinal()
    }

    override fun abort() {}
}

/** ECDH key agreement (PURPOSE_AGREE_KEY): the peer public key arrives via update()/finish(). */
private class KeyAgreer(private val privateKey: PrivateKey) : CryptoPrimitive {
    private val peerKey = ByteArrayOutputStream()

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) peerKey.write(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (data != null) peerKey.write(data)
        val peerPublicKey =
            KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(peerKey.toByteArray()))
        return KeyAgreement.getInstance("ECDH")
            .apply {
                init(privateKey)
                doPhase(peerPublicKey, true)
            }
            .generateSecret()
    }

    override fun abort() {}
}

// Concrete implementation for Encryption/Decryption.
private class CipherPrimitive(
    keyPair: KeyPair?,
    secretKey: SecretKey?,
    params: KeyMintAttestation,
    private val opMode: Int,
    /** IV to use; generated by the interceptor for randomized encryption. */
    private val iv: ByteArray?,
) : CryptoPrimitive {
    private val cipher: Cipher =
        Cipher.getInstance(transform(params)).apply {
            when (params.algorithm) {
                Algorithm.RSA -> {
                    val key = if (opMode == Cipher.ENCRYPT_MODE) keyPair!!.public else keyPair!!.private
                    when (params.padding.firstOrNull()) {
                        PaddingMode.RSA_OAEP -> {
                            val digestName =
                                params.digest.firstOrNull()?.let(JcaAlgorithmMapper::digestName)
                                    ?: "SHA1"
                            val mgf =
                                JcaAlgorithmMapper.mgf1Spec(
                                        params.rsaOaepMgfDigest.firstOrNull() ?: Digest.SHA1
                                    )
                                    ?: MGF1ParameterSpec.SHA1
                            init(
                                opMode,
                                key,
                                OAEPParameterSpec(
                                    digestName,
                                    "MGF1",
                                    mgf,
                                    PSource.PSpecified.DEFAULT,
                                ),
                            )
                        }
                        else -> init(opMode, key)
                    }
                }
                Algorithm.AES -> {
                    val spec =
                        when (params.blockMode.firstOrNull()) {
                            BlockMode.GCM -> GCMParameterSpec(128, iv)
                            BlockMode.CBC, BlockMode.CTR -> IvParameterSpec(iv)
                            else -> null
                        }
                    if (spec != null) init(opMode, secretKey, spec) else init(opMode, secretKey)
                }
                else ->
                    throw IllegalArgumentException("Unsupported cipher algorithm: ${params.algorithm}")
            }
        }

    private fun transform(params: KeyMintAttestation): String =
        when (params.algorithm) {
            Algorithm.RSA -> "RSA/ECB/${paddingName(params)}"
            Algorithm.AES -> "AES/${blockModeName(params)}/${symmetricPaddingName(params)}"
            else -> throw IllegalArgumentException("Unsupported cipher algorithm: ${params.algorithm}")
        }

    private fun paddingName(params: KeyMintAttestation): String =
        when (params.padding.firstOrNull()) {
            PaddingMode.RSA_PKCS1_1_5_ENCRYPT,
            PaddingMode.RSA_PKCS1_1_5_SIGN -> "PKCS1Padding"
            PaddingMode.RSA_OAEP -> "OAEPPadding"
            else -> "NoPadding"
        }

    private fun blockModeName(params: KeyMintAttestation): String =
        when (params.blockMode.firstOrNull()) {
            BlockMode.ECB -> "ECB"
            BlockMode.CBC -> "CBC"
            BlockMode.CTR -> "CTR"
            BlockMode.GCM -> "GCM"
            else -> "ECB"
        }

    private fun symmetricPaddingName(params: KeyMintAttestation): String =
        when (params.padding.firstOrNull()) {
            PaddingMode.PKCS7 -> "PKCS7Padding"
            else -> "NoPadding"
        }

    override fun updateAad(aad: ByteArray?) {
        if (aad != null) cipher.updateAAD(aad)
    }

    override fun update(data: ByteArray?): ByteArray? =
        if (data != null) cipher.update(data) else null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        var input = data ?: ByteArray(0)
        // For authenticated modes the tag is delivered through finish()'s signature argument.
        if (opMode == Cipher.DECRYPT_MODE && signature != null && signature.isNotEmpty()) {
            input = input + signature
        }
        return if (input.isNotEmpty()) cipher.doFinal(input) else cipher.doFinal()
    }

    override fun abort() {}
}

/**
 * A software-only implementation of a cryptographic operation. This class acts as a controller,
 * delegating to a specific cryptographic primitive based on the operation's purpose while
 * enforcing the key's authorizations like a hardware KeyMint backend would.
 */
class SoftwareOperation(
    private val txId: Long,
    keyPair: KeyPair?,
    secretKey: SecretKey?,
    keyParams: KeyMintAttestation,
    opParams: KeyMintAttestation,
    iv: ByteArray? = null,
) {
    // This now holds the specific strategy object (Signer, Verifier, etc.)
    private val primitive: CryptoPrimitive

    init {
        // Enforce the key's authorizations before selecting a primitive, exactly like a
        // KeyMint begin() would reject incompatible operations.
        AuthorizationChecker.check(keyParams, opParams)

        // The "Strategy" pattern: choose the implementation based on the purpose.
        val purpose = opParams.purpose.firstOrNull()
        val purposeName = KeyMintParameterLogger.purposeNames[purpose] ?: "UNKNOWN"
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Initializing for purpose: $purposeName.")

        primitive =
            when (purpose) {
                KeyPurpose.SIGN ->
                    if (opParams.algorithm == Algorithm.HMAC) {
                        MacPrimitive(secretKey!!, opParams)
                    } else {
                        Signer(keyPair!!.private, opParams)
                    }
                KeyPurpose.VERIFY ->
                    if (opParams.algorithm == Algorithm.HMAC) {
                        MacPrimitive(secretKey!!, opParams)
                    } else {
                        Verifier(keyPair!!.public, opParams)
                    }
                KeyPurpose.ENCRYPT ->
                    if (opParams.algorithm == Algorithm.HMAC) {
                        MacPrimitive(secretKey!!, opParams)
                    } else {
                        CipherPrimitive(keyPair, secretKey, opParams, Cipher.ENCRYPT_MODE, iv)
                    }
                KeyPurpose.DECRYPT ->
                    CipherPrimitive(keyPair, secretKey, opParams, Cipher.DECRYPT_MODE, iv)
                KeyPurpose.AGREE_KEY -> KeyAgreer(keyPair!!.private)
                else ->
                    throw KeyMintOperationException(
                        KeyMintErrors.INCOMPATIBLE_PURPOSE,
                        "Unsupported operation purpose: $purpose",
                    )
            }
    }

    fun updateAad(aad: ByteArray?) {
        try {
            primitive.updateAad(aad)
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update operation AAD.", e)
            throw e
        }
    }

    fun update(data: ByteArray?): ByteArray? {
        try {
            return primitive.update(data)
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update operation.", e)
            throw e
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        try {
            val result = primitive.finish(data, signature)
            SystemLogger.info("[SoftwareOp TX_ID: $txId] Finished operation successfully.")
            return result
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to finish operation.", e)
            // Re-throw the exception so the binder can report it to the client.
            throw e
        }
    }

    fun abort() {
        primitive.abort()
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Operation aborted.")
    }
}

/** The Binder interface for our [SoftwareOperation]. */
class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    @Throws(RemoteException::class)
    override fun updateAad(aadInput: ByteArray?) {
        return operation.updateAad(aadInput)
    }

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? {
        return operation.update(input)
    }

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
        return operation.finish(input, signature)
    }

    @Throws(RemoteException::class)
    override fun abort() {
        operation.abort()
    }
}
