package org.privacage.security

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import org.json.JSONObject
import org.privacage.android.StrictJsonKeyScanner

internal data class SignedPwnedManifestAttestation(
    val json: String,
    val manifestSha256: String,
    val signerPublicKeySha256: String
)

internal data class VerifiedPwnedManifestAttestation(
    val manifestSha256: String,
    val signerPublicKeySha256: String
)

/**
 * Portable, domain-separated P-256 ECDSA attestation format.
 *
 * The signature binds only the exact manifest digest to a public-key fingerprint.
 * It does not authenticate HIBP, prove range completeness, or establish trusted time.
 */
internal object PwnedPasswordManifestAttestation {
    const val MAX_BYTES = 4 * 1024
    const val FORMAT = "pcage-pwned-manifest-attestation"
    const val VERSION = 1
    const val SIGNATURE_ALGORITHM = "ECDSA-P256-SHA256"
    private const val JCA_SIGNATURE_ALGORITHM = "SHA256withECDSA"
    private const val DOMAIN = "PCAGE-PWNED-MANIFEST-ATTESTATION\u0000V1\u0000"

    private val digestPattern = Regex("[0-9A-F]{64}")
    private val fingerprintPattern = Regex("[0-9A-Fa-f]{64}")
    private val envelopeFields = setOf(
        "format",
        "version",
        "signature_algorithm",
        "manifest_sha256",
        "signer_public_key_x509_base64",
        "signer_public_key_sha256",
        "signature_base64"
    )

    @Throws(IOException::class)
    fun sign(
        manifestSha256: String,
        privateKey: PrivateKey,
        publicKey: PublicKey
    ): SignedPwnedManifestAttestation {
        val normalizedDigest = manifestSha256.uppercase()
        if (!digestPattern.matches(normalizedDigest)) {
            throw IOException("Manifest SHA-256 must contain exactly 64 hexadecimal characters.")
        }
        if (!privateKey.algorithm.equals("EC", ignoreCase = true) || !isP256PublicKey(publicKey)) {
            throw IOException("The attestation signer must be an EC P-256 key pair.")
        }
        val publicKeyBytes = publicKey.encoded
            ?: throw IOException("The attestation public key has no X.509 encoding.")
        if (publicKeyBytes.isEmpty() || publicKeyBytes.size > 256) {
            throw IOException("The attestation public key has an unsupported size.")
        }

        val manifestDigestBytes = decodeHexDigest(normalizedDigest)
        val publicKeyFingerprintBytes = sha256(publicKeyBytes)
        val fingerprint = toHex(publicKeyFingerprintBytes)
        val signingBytes = signingBytes(manifestDigestBytes, publicKeyFingerprintBytes)
        val signatureBytes = try {
            Signature.getInstance(JCA_SIGNATURE_ALGORITHM).run {
                initSign(privateKey)
                update(signingBytes)
                sign()
            }
        } catch (exception: Exception) {
            signingBytes.fill(0)
            manifestDigestBytes.fill(0)
            publicKeyFingerprintBytes.fill(0)
            throw IOException("The local attestation signature could not be created.", exception)
        }

        try {
            if (signatureBytes.isEmpty() || signatureBytes.size > 128) {
                throw IOException("The attestation signature has an unsupported size.")
            }
            val pairMatches = try {
                Signature.getInstance(JCA_SIGNATURE_ALGORITHM).run {
                    initVerify(publicKey)
                    update(signingBytes)
                    verify(signatureBytes)
                }
            } catch (exception: Exception) {
                throw IOException("The generated attestation signature could not be verified.", exception)
            }
            if (!pairMatches) throw IOException("The supplied private and public keys do not match.")

            val json = JSONObject()
                .put("format", FORMAT)
                .put("version", VERSION)
                .put("signature_algorithm", SIGNATURE_ALGORITHM)
                .put("manifest_sha256", normalizedDigest)
                .put("signer_public_key_x509_base64", Base64.getEncoder().encodeToString(publicKeyBytes))
                .put("signer_public_key_sha256", fingerprint)
                .put("signature_base64", Base64.getEncoder().encodeToString(signatureBytes))
                .toString() + "\n"
            if (json.toByteArray(StandardCharsets.UTF_8).size > MAX_BYTES) {
                throw IOException("The local attestation exceeds the 4 KiB output limit.")
            }
            return SignedPwnedManifestAttestation(json, normalizedDigest, fingerprint)
        } finally {
            manifestDigestBytes.fill(0)
            publicKeyFingerprintBytes.fill(0)
            signingBytes.fill(0)
            signatureBytes.fill(0)
        }
    }

    @Throws(IOException::class)
    fun verify(
        json: String,
        independentlyTrustedFingerprint: String
    ): VerifiedPwnedManifestAttestation {
        val encodedJson = json.toByteArray(StandardCharsets.UTF_8)
        if (encodedJson.isEmpty() || encodedJson.size > MAX_BYTES) {
            throw IOException("The attestation is empty or exceeds the 4 KiB input limit.")
        }
        try {
            StrictJsonKeyScanner.validate(json, "Pwned Passwords manifest attestation")
        } catch (exception: Exception) {
            throw IOException("The attestation JSON is malformed or contains duplicate keys.", exception)
        }
        val envelope = try {
            JSONObject(json)
        } catch (exception: Exception) {
            throw IOException("The attestation is not valid JSON.", exception)
        }
        val actualFields = envelope.keys().asSequence().toSet()
        if (actualFields != envelopeFields) {
            throw IOException("The attestation has missing or unsupported fields.")
        }
        if (requiredString(envelope, "format") != FORMAT ||
            requiredInteger(envelope, "version") != VERSION ||
            requiredString(envelope, "signature_algorithm") != SIGNATURE_ALGORITHM
        ) {
            throw IOException("Unsupported Pwned Passwords attestation format or algorithm.")
        }

        val manifestDigest = requiredString(envelope, "manifest_sha256")
        if (!digestPattern.matches(manifestDigest)) {
            throw IOException("The attestation manifest digest is not canonical uppercase SHA-256.")
        }
        if (!fingerprintPattern.matches(independentlyTrustedFingerprint)) {
            throw IOException("The independently trusted public-key fingerprint is invalid.")
        }

        val publicKeyBase64 = requiredString(envelope, "signer_public_key_x509_base64")
        val signatureBase64 = requiredString(envelope, "signature_base64")
        if (publicKeyBase64.length > 512 || signatureBase64.length > 256) {
            throw IOException("The attestation key or signature exceeds its encoded size limit.")
        }
        val publicKeyBytes = decodeBase64(publicKeyBase64, "public key")
        if (publicKeyBytes.isEmpty() || publicKeyBytes.size > 256) {
            publicKeyBytes.fill(0)
            throw IOException("The attestation public key has an unsupported size.")
        }
        val publicKey = try {
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeyBytes))
        } catch (exception: Exception) {
            publicKeyBytes.fill(0)
            throw IOException("The attestation does not contain a valid EC public key.", exception)
        }
        if (!isP256PublicKey(publicKey) || !publicKey.encoded.contentEquals(publicKeyBytes)) {
            publicKeyBytes.fill(0)
            throw IOException("The attestation public key is not canonical P-256 X.509 data.")
        }

        val publicKeyFingerprintBytes = sha256(publicKeyBytes)
        val actualFingerprint = toHex(publicKeyFingerprintBytes)
        val declaredFingerprint = requiredString(envelope, "signer_public_key_sha256")
        if (!digestPattern.matches(declaredFingerprint) || declaredFingerprint != actualFingerprint) {
            publicKeyBytes.fill(0)
            publicKeyFingerprintBytes.fill(0)
            throw IOException("The attestation public-key fingerprint does not match its key.")
        }
        val trustedFingerprintBytes = decodeHexDigest(independentlyTrustedFingerprint.uppercase())
        if (!MessageDigest.isEqual(publicKeyFingerprintBytes, trustedFingerprintBytes)) {
            publicKeyBytes.fill(0)
            publicKeyFingerprintBytes.fill(0)
            trustedFingerprintBytes.fill(0)
            throw IOException("The attestation signer does not match the independently trusted fingerprint.")
        }

        val manifestDigestBytes = decodeHexDigest(manifestDigest)
        val message = signingBytes(manifestDigestBytes, publicKeyFingerprintBytes)
        val signatureBytes = decodeBase64(signatureBase64, "signature")
        try {
            if (signatureBytes.isEmpty() || signatureBytes.size > 128) {
                throw IOException("The attestation signature has an unsupported size.")
            }
            val valid = try {
                Signature.getInstance(JCA_SIGNATURE_ALGORITHM).run {
                    initVerify(publicKey)
                    update(message)
                    verify(signatureBytes)
                }
            } catch (exception: Exception) {
                throw IOException("The attestation signature could not be verified.", exception)
            }
            if (!valid) throw IOException("The attestation signature is invalid.")
            return VerifiedPwnedManifestAttestation(manifestDigest, actualFingerprint)
        } finally {
            publicKeyBytes.fill(0)
            publicKeyFingerprintBytes.fill(0)
            trustedFingerprintBytes.fill(0)
            manifestDigestBytes.fill(0)
            message.fill(0)
            signatureBytes.fill(0)
        }
    }

    private fun requiredString(value: JSONObject, key: String): String =
        value.opt(key) as? String ?: throw IOException("Attestation field " + key + " must be a string.")

    private fun requiredInteger(value: JSONObject, key: String): Int {
        val number = value.opt(key) as? Number
            ?: throw IOException("Attestation field " + key + " must be an integer.")
        if (number.toString() != VERSION.toString()) {
            throw IOException("Attestation field " + key + " is not the canonical supported integer.")
        }
        return VERSION
    }

    private fun decodeBase64(value: String, label: String): ByteArray {
        val decoded = try {
            Base64.getDecoder().decode(value)
        } catch (exception: Exception) {
            throw IOException("The attestation " + label + " is not valid Base64.", exception)
        }
        if (Base64.getEncoder().encodeToString(decoded) != value) {
            decoded.fill(0)
            throw IOException("The attestation " + label + " is not canonical Base64.")
        }
        return decoded
    }

    private fun decodeHexDigest(value: String): ByteArray {
        if (!digestPattern.matches(value)) throw IOException("A canonical SHA-256 digest is required.")
        return ByteArray(32) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

    private fun signingBytes(manifestDigest: ByteArray, publicKeyFingerprint: ByteArray): ByteArray {
        val domain = DOMAIN.toByteArray(StandardCharsets.US_ASCII)
        if (manifestDigest.size != 32 || publicKeyFingerprint.size != 32) {
            throw IOException("Attestation signing inputs have invalid digest lengths.")
        }
        return ByteArray(domain.size + 64).also { output ->
            System.arraycopy(domain, 0, output, 0, domain.size)
            System.arraycopy(manifestDigest, 0, output, domain.size, 32)
            System.arraycopy(publicKeyFingerprint, 0, output, domain.size + 32, 32)
        }
    }

    private fun toHex(value: ByteArray): String =
        value.joinToString("") { "%02X".format(it.toInt() and 0xff) }

    private fun isP256PublicKey(publicKey: PublicKey): Boolean {
        val actual = (publicKey as? ECPublicKey)?.params ?: return false
        val expected = try {
            AlgorithmParameters.getInstance("EC").apply {
                init(ECGenParameterSpec("secp256r1"))
            }.getParameterSpec(ECParameterSpec::class.java)
        } catch (_: Exception) {
            return false
        }
        return actual.curve == expected.curve &&
            actual.generator == expected.generator &&
            actual.order == expected.order &&
            actual.cofactor == expected.cofactor
    }
}
