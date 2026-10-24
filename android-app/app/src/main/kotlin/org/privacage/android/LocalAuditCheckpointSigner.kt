package org.privacage.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import org.privacage.audit.AuditChainRecord
import org.privacage.audit.AuditIntegrityChain
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant

internal data class SignedAuditCheckpoint(
    val json: String,
    val createdAt: String,
    val publicKeySha256: String,
    val payloadSha256: String
)

internal data class AuditCheckpointVerification(
    val signatureValid: Boolean,
    val payloadHashValid: Boolean,
    val chainValid: Boolean,
    val signerMatchesThisInstallation: Boolean,
    val signerPublicKeySha256: String,
    val createdAt: String,
    val eventCount: Int,
    val detail: String
) {
    fun render(): String = buildString {
        append("AUDIT CHECKPOINT VERIFICATION\n")
        append("Created at (device clock): ").append(createdAt).append('\n')
        append("Signer public-key SHA-256: ").append(signerPublicKeySha256).append('\n')
        append("Event count: ").append(eventCount).append('\n')
        append("Signature: ").append(if (signatureValid) "VALID" else "INVALID").append('\n')
        append("Payload hash: ").append(if (payloadHashValid) "MATCH" else "MISMATCH").append('\n')
        append("Event hash chain: ").append(if (chainValid) "VALID" else "INVALID").append('\n')
        append("Signer key matches this installation: ").append(if (signerMatchesThisInstallation) "YES" else "NO / NOT ESTABLISHED")
        append("\n\n").append(detail)
        append("\n\nThe embedded public key proves only that this file was signed by the corresponding key. It does not identify a person or prove a trusted timestamp. Compare the fingerprint through a separate trusted channel.")
    }
}

/**
 * Signs audit snapshots with a non-exportable Android Keystore P-256 private key.
 * Key loss is not silently repaired during verification; old checkpoints become unanchored
 * unless their signer fingerprint is independently trusted.
 */
internal object LocalAuditCheckpointSigner {
    private const val KEY_ALIAS = "org.privacage.audit.checkpoint.p256.v1"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    fun sign(
        context: Context,
        payloadJson: String,
        chainHeadSha256: String,
        eventCount: Int,
        createdAt: Instant = Instant.now()
    ): SignedAuditCheckpoint {
        val keyPair = loadOrCreateKeyPair()
        val createdAtText = createdAt.toString()
        val payloadBytes = payloadJson.toByteArray(StandardCharsets.UTF_8)
        try {
            val payloadSha256 = AuditIntegrityChain.sha256Hex(payloadBytes)
            val publicKeySha256 = AuditIntegrityChain.sha256Hex(keyPair.public.encoded)
            val signingBytes = AuditIntegrityChain.checkpointSigningBytes(
                createdAtText,
                payloadSha256,
                chainHeadSha256,
                eventCount,
                publicKeySha256
            )
            val signatureBytes = Signature.getInstance(AuditIntegrityChain.CHECKPOINT_SIGNATURE_ALGORITHM).run {
                initSign(keyPair.private)
                update(signingBytes)
                sign()
            }
            val envelope = JSONObject()
                .put("format", AuditIntegrityChain.CHECKPOINT_FORMAT)
                .put("schema_version", AuditIntegrityChain.CHECKPOINT_SCHEMA_VERSION)
                .put("signature_algorithm", AuditIntegrityChain.CHECKPOINT_SIGNATURE_ALGORITHM)
                .put("created_at", createdAtText)
                .put("signer_public_key_x509_base64", Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP))
                .put("signer_public_key_sha256", publicKeySha256)
                .put("payload_sha256", payloadSha256)
                .put("chain_head_sha256", chainHeadSha256)
                .put("event_count", eventCount)
                .put("signature_base64", Base64.encodeToString(signatureBytes, Base64.NO_WRAP))
                .put("payload_json", payloadJson)
            signatureBytes.fill(0)
            signingBytes.fill(0)
            return SignedAuditCheckpoint(
                json = envelope.toString(2) + "\n",
                createdAt = createdAtText,
                publicKeySha256 = publicKeySha256,
                payloadSha256 = payloadSha256
            )
        } finally {
            payloadBytes.fill(0)
        }
    }

    fun verify(context: Context, checkpointJson: String): AuditCheckpointVerification {
        val envelope = try {
            JSONObject(checkpointJson)
        } catch (exception: Exception) {
            throw IOException("The selected checkpoint is not valid JSON.", exception)
        }
        if (requiredString(envelope, "format") != AuditIntegrityChain.CHECKPOINT_FORMAT ||
            envelope.optInt("schema_version", -1) != AuditIntegrityChain.CHECKPOINT_SCHEMA_VERSION
        ) {
            throw IOException("Unsupported PrivaCage audit checkpoint format.")
        }
        if (requiredString(envelope, "signature_algorithm") != AuditIntegrityChain.CHECKPOINT_SIGNATURE_ALGORITHM) {
            throw IOException("Unsupported audit checkpoint signature algorithm.")
        }

        val createdAt = requiredString(envelope, "created_at")
        val payloadSha256 = requiredString(envelope, "payload_sha256")
        val chainHeadSha256 = requiredString(envelope, "chain_head_sha256")
        val publicKeySha256 = requiredString(envelope, "signer_public_key_sha256")
        val signatureBase64 = requiredString(envelope, "signature_base64")
        val payloadJson = requiredString(envelope, "payload_json")
        val publicKeyBytes = try {
            Base64.decode(requiredString(envelope, "signer_public_key_x509_base64"), Base64.NO_WRAP)
        } catch (exception: Exception) {
            throw IOException("The checkpoint public key is not valid Base64.", exception)
        }
        val publicKey = try {
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeyBytes))
        } catch (exception: Exception) {
            throw IOException("The checkpoint does not contain a supported EC public key.", exception)
        } finally {
            publicKeyBytes.fill(0)
        }
        if (AuditIntegrityChain.sha256Hex(publicKey.encoded) != publicKeySha256) {
            throw IOException("The checkpoint public-key fingerprint does not match its key bytes.")
        }

        val eventCount = envelope.optInt("event_count", -1)
        if (eventCount < 0) throw IOException("The checkpoint event count is missing or invalid.")
        val payloadBytes = payloadJson.toByteArray(StandardCharsets.UTF_8)
        val payloadHashValid = try {
            AuditIntegrityChain.sha256Hex(payloadBytes) == payloadSha256
        } finally {
            payloadBytes.fill(0)
        }

        val chainCheck = try {
            verifyPayloadChain(payloadJson, chainHeadSha256, eventCount)
        } catch (_: Exception) {
            null
        }
        val chainValid = chainCheck?.valid == true
        val signingBytes = try {
            AuditIntegrityChain.checkpointSigningBytes(
                createdAt, payloadSha256, chainHeadSha256, eventCount, publicKeySha256
            )
        } catch (exception: Exception) {
            throw IOException("Checkpoint signature metadata is invalid.", exception)
        }
        val signatureValid = try {
            AuditIntegrityChain.verifySignature(publicKey, signingBytes, signatureBase64)
        } finally {
            signingBytes.fill(0)
        }
        val signerMatches = currentInstallationPublicKey()?.encoded?.contentEquals(publicKey.encoded) == true

        val detail = when {
            !signatureValid -> "The signature does not match the checkpoint metadata. Treat this file as altered or invalid."
            !payloadHashValid -> "The signature is valid for its recorded metadata, but the embedded payload bytes have changed."
            !chainValid -> "The signature and/or event chain did not validate against the checkpoint's claimed record count and head."
            signerMatches -> "Signature, payload digest and event chain validate. The signer key matches the key currently stored in this installation's Android Keystore."
            else -> "The signature, payload digest and event chain validate cryptographically, but this installation does not have the same signer key. The embedded public key alone does not establish who created the file."
        }
        return AuditCheckpointVerification(
            signatureValid = signatureValid,
            payloadHashValid = payloadHashValid,
            chainValid = chainValid,
            signerMatchesThisInstallation = signerMatches,
            signerPublicKeySha256 = publicKeySha256,
            createdAt = createdAt,
            eventCount = eventCount,
            detail = detail
        )
    }

    private fun verifyPayloadChain(
        payloadJson: String,
        outerHeadSha256: String,
        outerEventCount: Int
    ): org.privacage.audit.AuditChainVerification {
        val payload = JSONObject(payloadJson)
        val events = payload.optJSONArray("events")
            ?: throw IOException("Checkpoint payload does not include an events array.")
        val integrity = payload.optJSONObject("integrity")
            ?: throw IOException("Checkpoint payload does not include chain metadata.")
        val innerHead = requiredString(integrity, "chain_head_sha256")
        val innerAlgorithm = requiredString(integrity, "algorithm")
        if (innerAlgorithm != AuditIntegrityChain.ALGORITHM || innerHead != outerHeadSha256 ||
            integrity.optInt("record_count", -1) != outerEventCount ||
            payload.optInt("event_count", -1) != outerEventCount ||
            events.length() != outerEventCount
        ) {
            return org.privacage.audit.AuditChainVerification(
                false, events.length(), innerHead, "checkpoint and payload integrity metadata disagree"
            )
        }

        val records = ArrayList<AuditChainRecord>(events.length())
        for (index in 0 until events.length()) {
            val item = events.optJSONObject(index)
                ?: throw IOException("Checkpoint event $index is not an object.")
            records += AuditChainRecord(
                timestamp = requiredString(item, "timestamp"),
                localDate = requiredString(item, "local_date"),
                category = requiredString(item, "category"),
                queriedHostname = requiredString(item, "queried_hostname"),
                socketOwnerLabel = requiredString(item, "socket_owner_label"),
                previousRecordSha256 = requiredString(item, "previous_record_sha256"),
                recordSha256 = requiredString(item, "record_sha256")
            )
        }
        return AuditIntegrityChain.verify(records, outerHeadSha256, outerEventCount)
    }

    private fun requiredString(value: JSONObject, key: String): String {
        return value.opt(key) as? String
            ?: throw IOException("Checkpoint field '$key' is missing or is not a string.")
    }

    private fun loadOrCreateKeyPair(): KeyPair {
        var keyStore = androidKeyStore()
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            generator.initialize(
                KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            generator.generateKeyPair()
            keyStore = androidKeyStore()
        }
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
            ?: throw IOException("The audit signing key exists but Android Keystore did not provide its private-key handle. It was not replaced.")
        val certificate = keyStore.getCertificate(KEY_ALIAS)
            ?: throw IOException("The audit signing key has no public-key certificate. It was not replaced.")
        return KeyPair(certificate.publicKey, privateKey)
    }

    private fun currentInstallationPublicKey(): java.security.PublicKey? = try {
        val keyStore = androidKeyStore()
        if (!keyStore.containsAlias(KEY_ALIAS)) null else keyStore.getCertificate(KEY_ALIAS)?.publicKey
    } catch (_: Exception) {
        null
    }

    private fun androidKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
}
