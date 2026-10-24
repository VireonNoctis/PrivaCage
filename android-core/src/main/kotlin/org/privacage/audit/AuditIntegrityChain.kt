package org.privacage.audit

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.time.Instant
import java.util.Base64

data class AuditChainInput(
    val timestamp: String,
    val localDate: String,
    val category: String,
    val queriedHostname: String,
    val socketOwnerLabel: String
)

data class AuditChainRecord(
    val timestamp: String,
    val localDate: String,
    val category: String,
    val queriedHostname: String,
    val socketOwnerLabel: String,
    val previousRecordSha256: String,
    val recordSha256: String
)

data class AuditChainVerification(
    val valid: Boolean,
    val checkedRecords: Int,
    val headSha256: String,
    val failureReason: String? = null
)

/**
 * Deterministic SHA-256 event chain and signature helpers shared by Android and JVM tests.
 *
 * The chain detects edits relative to a trusted head. Only a signed checkpoint anchors that head;
 * signing keys and their trust decisions remain platform-specific.
 */
object AuditIntegrityChain {
    const val ALGORITHM = "sha256-chain-v1"
    const val CHECKPOINT_SIGNATURE_ALGORITHM = "SHA256withECDSA"
    const val CHECKPOINT_FORMAT = "privacage-audit-checkpoint"
    const val CHECKPOINT_SCHEMA_VERSION = 1
    const val GENESIS_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

    private const val RECORD_DOMAIN = "PrivaCage-Audit-Record-v1"
    private const val CHECKPOINT_DOMAIN = "PrivaCage-Audit-Checkpoint-v1"
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun create(inputs: List<AuditChainInput>): List<AuditChainRecord> {
        var previous = GENESIS_SHA256
        return inputs.map { input ->
            val digest = recordDigest(previous, input)
            AuditChainRecord(
                timestamp = input.timestamp,
                localDate = input.localDate,
                category = input.category,
                queriedHostname = input.queriedHostname,
                socketOwnerLabel = input.socketOwnerLabel,
                previousRecordSha256 = previous,
                recordSha256 = digest
            ).also {
                previous = digest
            }
        }
    }

    fun verify(
        records: List<AuditChainRecord>,
        expectedHeadSha256: String,
        expectedRecordCount: Int
    ): AuditChainVerification {
        if (expectedRecordCount < 0 || expectedRecordCount != records.size) {
            return AuditChainVerification(
                false, records.size, records.lastOrNull()?.recordSha256 ?: GENESIS_SHA256,
                "record count does not match the signed checkpoint"
            )
        }
        if (!sha256Pattern.matches(expectedHeadSha256)) {
            return AuditChainVerification(false, records.size, GENESIS_SHA256, "checkpoint head is not a SHA-256 hex digest")
        }

        var previous = GENESIS_SHA256
        for ((index, record) in records.withIndex()) {
            if (record.previousRecordSha256 != previous) {
                return AuditChainVerification(
                    false, index, previous, "previous-hash mismatch at record \${index + 1}"
                )
            }
            if (!sha256Pattern.matches(record.recordSha256)) {
                return AuditChainVerification(
                    false, index, previous, "record \${index + 1} has an invalid hash encoding"
                )
            }
            val input = AuditChainInput(
                record.timestamp,
                record.localDate,
                record.category,
                record.queriedHostname,
                record.socketOwnerLabel
            )
            val calculated = recordDigest(previous, input)
            if (calculated != record.recordSha256) {
                return AuditChainVerification(
                    false, index, previous, "record hash mismatch at record \${index + 1}"
                )
            }
            previous = calculated
        }

        if (previous != expectedHeadSha256) {
            return AuditChainVerification(false, records.size, previous, "chain head does not match the signed checkpoint")
        }
        return AuditChainVerification(true, records.size, previous)
    }

    fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val digits = "0123456789abcdef"
        return buildString(64) {
            for (byte in digest) {
                val value = byte.toInt() and 0xff
                append(digits[value ushr 4])
                append(digits[value and 0x0f])
            }
        }
    }

    fun sha256Hex(value: String): String = sha256Hex(value.toByteArray(StandardCharsets.UTF_8))

    fun checkpointSigningBytes(
        createdAt: String,
        payloadSha256: String,
        chainHeadSha256: String,
        eventCount: Int,
        signerPublicKeySha256: String
    ): ByteArray {
        require(Instant.parse(createdAt).toString() == createdAt) {
            "Checkpoint creation time must be a canonical ISO-8601 instant."
        }
        require(sha256Pattern.matches(payloadSha256)) { "Payload SHA-256 is invalid." }
        require(sha256Pattern.matches(chainHeadSha256)) { "Chain-head SHA-256 is invalid." }
        require(eventCount >= 0) { "Checkpoint event count cannot be negative." }
        require(sha256Pattern.matches(signerPublicKeySha256)) { "Signer-key SHA-256 is invalid." }

        return buildString {
            append(CHECKPOINT_DOMAIN).append('\n')
            append("schema_version=").append(CHECKPOINT_SCHEMA_VERSION).append('\n')
            append("signature_algorithm=").append(CHECKPOINT_SIGNATURE_ALGORITHM).append('\n')
            append("created_at=").append(createdAt).append('\n')
            append("payload_sha256=").append(payloadSha256).append('\n')
            append("chain_head_sha256=").append(chainHeadSha256).append('\n')
            append("event_count=").append(eventCount).append('\n')
            append("signer_public_key_sha256=").append(signerPublicKeySha256).append('\n')
        }.toByteArray(StandardCharsets.UTF_8)
    }

    fun verifySignature(publicKey: PublicKey, signingBytes: ByteArray, signatureBase64: String): Boolean {
        return try {
            val signatureBytes = Base64.getDecoder().decode(signatureBase64)
            Signature.getInstance(CHECKPOINT_SIGNATURE_ALGORITHM).run {
                initVerify(publicKey)
                update(signingBytes)
                verify(signatureBytes)
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun recordDigest(previousHash: String, input: AuditChainInput): String {
        require(sha256Pattern.matches(previousHash)) { "Previous record hash is invalid." }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(RECORD_DOMAIN.toByteArray(StandardCharsets.US_ASCII))
        digest.update('\n'.code.toByte())
        digest.update(previousHash.toByteArray(StandardCharsets.US_ASCII))
        digest.update('\n'.code.toByte())

        listOf(
            input.timestamp,
            input.localDate,
            input.category,
            input.queriedHostname,
            input.socketOwnerLabel
        ).forEach { field ->
            val bytes = field.toByteArray(StandardCharsets.UTF_8)
            digest.update(bytes.size.toString().toByteArray(StandardCharsets.US_ASCII))
            digest.update(':'.code.toByte())
            digest.update(bytes)
            digest.update('\n'.code.toByte())
            bytes.fill(0)
        }
        return sha256Hex(digest.digest())
    }
}
