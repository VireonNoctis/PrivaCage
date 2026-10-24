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
import java.security.AlgorithmParameters
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

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
    private const val MAX_CHECKPOINT_BYTES = 2 * 1024 * 1024
    private const val MAX_PAYLOAD_BYTES = 1024 * 1024
    private const val MAX_EVENT_COUNT = 100

    private val envelopeKeys = setOf(
        "format", "schema_version", "signature_algorithm", "created_at",
        "signer_public_key_x509_base64", "signer_public_key_sha256", "payload_sha256",
        "chain_head_sha256", "event_count", "signature_base64", "payload_json"
    )

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
        if (checkpointJson.length > MAX_CHECKPOINT_BYTES) {
            throw IOException("The selected checkpoint exceeds the 2 MiB size limit.")
        }
        val checkpointBytes = checkpointJson.toByteArray(StandardCharsets.UTF_8)
        try {
            if (checkpointBytes.size > MAX_CHECKPOINT_BYTES) {
                throw IOException("The selected checkpoint exceeds the 2 MiB size limit.")
            }
        } finally {
            checkpointBytes.fill(0)
        }
        val envelope = try {
            JSONObject(checkpointJson)
        } catch (exception: Exception) {
            throw IOException("The selected checkpoint is not valid JSON.", exception)
        }
        requireOnlyKeys(envelope, envelopeKeys, "checkpoint")
        if (requiredString(envelope, "format") != AuditIntegrityChain.CHECKPOINT_FORMAT ||
            requiredInt(envelope, "schema_version") != AuditIntegrityChain.CHECKPOINT_SCHEMA_VERSION
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
        if (payloadJson.toByteArray(StandardCharsets.UTF_8).size > MAX_PAYLOAD_BYTES) {
            throw IOException("The embedded audit payload exceeds the 1 MiB size limit.")
        }
        val publicKeyBase64 = requiredString(envelope, "signer_public_key_x509_base64")
        if (publicKeyBase64.length > 512) throw IOException("The checkpoint public key exceeds the size limit.")
        val signatureBytesText = signatureBase64
        if (signatureBytesText.length > 256) throw IOException("The checkpoint signature exceeds the size limit.")
        val publicKeyBytes = try {
            Base64.decode(publicKeyBase64, Base64.NO_WRAP)
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
        if (!isP256PublicKey(publicKey)) {
            throw IOException("The checkpoint signer must use the P-256 elliptic curve.")
        }
        if (AuditIntegrityChain.sha256Hex(publicKey.encoded) != publicKeySha256) {
            throw IOException("The checkpoint public-key fingerprint does not match its key bytes.")
        }

        val eventCount = requiredInt(envelope, "event_count")
        if (eventCount !in 0..MAX_EVENT_COUNT) {
            throw IOException("The checkpoint event count is outside the supported 0..100 range.")
        }
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
        requireOnlyKeys(
            payload,
            setOf(
                "schema_version", "source", "generated_at", "filter_timezone", "date_range",
                "selected_categories", "integrity", "redactions", "records_read",
                "records_skipped_invalid", "records_excluded_by_filters", "event_count", "events"
            ),
            "audit payload"
        )
        if (requiredInt(payload, "schema_version") != 1 ||
            requiredString(payload, "source") != "optional_local_dns_event_history"
        ) {
            throw IOException("Unsupported audit payload schema or source.")
        }
        val generatedAt = requiredString(payload, "generated_at")
        if (Instant.parse(generatedAt).toString() != generatedAt) {
            throw IOException("Audit payload generation time is not canonical.")
        }
        val timezoneId = requiredString(payload, "filter_timezone")
        val zoneId = try {
            ZoneId.of(timezoneId)
        } catch (exception: Exception) {
            throw IOException("Audit payload time zone is invalid.", exception)
        }
        val dateRange = payload.optJSONObject("date_range")
            ?: throw IOException("Audit payload date range is missing.")
        requireOnlyKeys(dateRange, setOf("start_inclusive", "end_inclusive"), "date range")
        val startDate = try {
            LocalDate.parse(requiredString(dateRange, "start_inclusive"))
        } catch (exception: Exception) {
            throw IOException("Audit payload start date is invalid.", exception)
        }
        val endDate = try {
            LocalDate.parse(requiredString(dateRange, "end_inclusive"))
        } catch (exception: Exception) {
            throw IOException("Audit payload end date is invalid.", exception)
        }
        if (startDate.isAfter(endDate)) throw IOException("Audit payload date range is reversed.")

        val selectedCategories = payload.optJSONArray("selected_categories")
            ?: throw IOException("Audit payload selected categories are missing.")
        if (selectedCategories.length() == 0) throw IOException("Audit payload selected categories are empty.")
        val categoryList = (0 until selectedCategories.length()).map { index ->
            selectedCategories.opt(index) as? String
                ?: throw IOException("Audit payload selected category is not a string.")
        }
        if (categoryList.any { it !in setOf("BLOCKED", "FORWARDED") } ||
            categoryList != categoryList.distinct().sorted()
        ) {
            throw IOException("Audit payload selected categories are unsupported, duplicated, or unsorted.")
        }

        val redactions = payload.optJSONObject("redactions")
            ?: throw IOException("Audit payload redaction metadata is missing.")
        requireOnlyKeys(
            redactions,
            setOf("queried_hostnames", "socket_owner_labels", "device_identifiers", "internal_file_paths", "packet_payloads"),
            "redaction metadata"
        )
        val hostnamesRedacted = requiredBoolean(redactions, "queried_hostnames")
        val ownersRedacted = requiredBoolean(redactions, "socket_owner_labels")
        if (!requiredBoolean(redactions, "device_identifiers") ||
            !requiredBoolean(redactions, "internal_file_paths") ||
            !requiredBoolean(redactions, "packet_payloads")
        ) {
            throw IOException("Audit payload makes a false fixed-redaction claim.")
        }

        val recordsRead = requiredInt(payload, "records_read")
        val recordsSkipped = requiredInt(payload, "records_skipped_invalid")
        val recordsExcluded = requiredInt(payload, "records_excluded_by_filters")
        if (recordsRead !in 0..MAX_EVENT_COUNT ||
            recordsSkipped !in 0..MAX_EVENT_COUNT ||
            recordsExcluded !in 0..MAX_EVENT_COUNT ||
            recordsSkipped + recordsExcluded + outerEventCount != recordsRead
        ) {
            throw IOException("Audit payload record counters do not account for the bounded history.")
        }

        val events = payload.optJSONArray("events")
            ?: throw IOException("Checkpoint payload does not include an events array.")
        val integrity = payload.optJSONObject("integrity")
            ?: throw IOException("Checkpoint payload does not include chain metadata.")
        requireOnlyKeys(
            integrity,
            setOf("algorithm", "genesis_sha256", "chain_head_sha256", "record_count"),
            "integrity metadata"
        )
        val innerHead = requiredString(integrity, "chain_head_sha256")
        val innerAlgorithm = requiredString(integrity, "algorithm")
        if (innerAlgorithm != AuditIntegrityChain.ALGORITHM ||
            requiredString(integrity, "genesis_sha256") != AuditIntegrityChain.GENESIS_SHA256 ||
            innerHead != outerHeadSha256 ||
            requiredInt(integrity, "record_count") != outerEventCount ||
            requiredInt(payload, "event_count") != outerEventCount ||
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
            requireOnlyKeys(
                item,
                setOf(
                    "timestamp", "local_date", "category", "queried_hostname", "socket_owner_label",
                    "previous_record_sha256", "record_sha256"
                ),
                "audit event"
            )
            val timestampText = requiredString(item, "timestamp")
            val timestamp = try {
                Instant.parse(timestampText)
            } catch (exception: Exception) {
                throw IOException("Checkpoint event $index has an invalid timestamp.", exception)
            }
            if (timestamp.toString() != timestampText) {
                throw IOException("Checkpoint event $index timestamp is not canonical.")
            }
            val localDateText = requiredString(item, "local_date")
            val localDate = try {
                LocalDate.parse(localDateText)
            } catch (exception: Exception) {
                throw IOException("Checkpoint event $index has an invalid local date.", exception)
            }
            if (localDate.toString() != localDateText ||
                localDate.isBefore(startDate) || localDate.isAfter(endDate) ||
                timestamp.atZone(zoneId).toLocalDate() != localDate
            ) {
                throw IOException("Checkpoint event $index date is inconsistent with the timestamp or filter range.")
            }
            val category = requiredString(item, "category")
            if (category !in categoryList) {
                throw IOException("Checkpoint event $index category was not selected for export.")
            }
            val hostname = requiredString(item, "queried_hostname")
            if (hostnamesRedacted && hostname != "[REDACTED]") {
                throw IOException("Checkpoint event $index contains a hostname despite claiming it was redacted.")
            }
            val ownerLabel = requiredString(item, "socket_owner_label")
            if (ownersRedacted && ownerLabel != "[REDACTED]") {
                throw IOException("Checkpoint event $index contains a socket-owner label despite claiming it was redacted.")
            }
            records += AuditChainRecord(
                timestamp = timestampText,
                localDate = localDateText,
                category = category,
                queriedHostname = hostname,
                socketOwnerLabel = ownerLabel,
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

    private fun requiredInt(value: JSONObject, key: String): Int {
        val raw = value.opt(key)
        return when (raw) {
            is Int -> raw
            is Long -> if (raw in 0L..Int.MAX_VALUE.toLong()) raw.toInt()
                else throw IOException("Checkpoint integer field '$key' is out of range.")
            else -> throw IOException("Checkpoint field '$key' must be an integer JSON number.")
        }.also {
            if (it < 0) throw IOException("Checkpoint field '$key' must not be negative.")
        }
    }

    private fun requiredBoolean(value: JSONObject, key: String): Boolean =
        value.opt(key) as? Boolean
            ?: throw IOException("Checkpoint field '$key' must be a JSON boolean.")

    private fun requireOnlyKeys(value: JSONObject, allowed: Set<String>, label: String) {
        val keys = value.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            if (key !in allowed) throw IOException("Unsupported field '$key' in $label.")
        }
    }

    private fun isP256PublicKey(publicKey: java.security.PublicKey): Boolean {
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
