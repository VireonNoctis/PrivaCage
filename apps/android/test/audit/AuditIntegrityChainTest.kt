package org.privacage.audit

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuditIntegrityChainTest {
    private val records = AuditIntegrityChain.create(
        listOf(
            AuditChainInput("2026-10-24T10:00:00Z", "2026-10-24", "BLOCKED", "[REDACTED]", "[REDACTED]"),
            AuditChainInput("2026-10-24T10:01:00Z", "2026-10-24", "FORWARDED", "chosen.example", "[REDACTED]"),
            AuditChainInput("2026-10-24T10:02:00Z", "2026-10-24", "BLOCKED", "third.example", "Android resolver")
        )
    )

    @Test
    fun verifiesAnUntamperedChainAndEmptyGenesis() {
        val verified = AuditIntegrityChain.verify(records, records.last().recordSha256, records.size)
        assertTrue(verified.valid)
        assertEquals(records.size, verified.checkedRecords)
        assertEquals(records.last().recordSha256, verified.headSha256)

        val empty = AuditIntegrityChain.verify(emptyList(), AuditIntegrityChain.GENESIS_SHA256, 0)
        assertTrue(empty.valid)
        assertEquals(AuditIntegrityChain.GENESIS_SHA256, empty.headSha256)
    }

    @Test
    fun detectsModifiedRecordContent() {
        val modified = records.toMutableList()
        modified[1] = modified[1].copy(queriedHostname = "attacker.example")
        val result = AuditIntegrityChain.verify(modified, records.last().recordSha256, records.size)
        assertFalse(result.valid)
        assertNotNull(result.failureReason)
    }

    @Test
    fun detectsReorderingAndDeletion() {
        val reordered = listOf(records[1], records[0], records[2])
        assertFalse(AuditIntegrityChain.verify(reordered, records.last().recordSha256, records.size).valid)

        val deleted = listOf(records[0], records[2])
        assertFalse(AuditIntegrityChain.verify(deleted, records.last().recordSha256, records.size).valid)
    }

    @Test
    fun detectsTruncationAgainstSignedCountAndHead() {
        val truncated = records.dropLast(1)
        val result = AuditIntegrityChain.verify(truncated, records.last().recordSha256, records.size)
        assertFalse(result.valid)
        assertEquals("record count does not match the signed checkpoint", result.failureReason)
    }

    @Test
    fun detectsAnAlteredRecordHashOrPreviousLink() {
        val badHash = records.toMutableList()
        badHash[0] = badHash[0].copy(recordSha256 = "f".repeat(64))
        assertFalse(AuditIntegrityChain.verify(badHash, records.last().recordSha256, records.size).valid)

        val badLink = records.toMutableList()
        badLink[1] = badLink[1].copy(previousRecordSha256 = "e".repeat(64))
        assertFalse(AuditIntegrityChain.verify(badLink, records.last().recordSha256, records.size).valid)
    }

    @Test
    fun verifiesEcdsaCheckpointSignaturesAndRejectsChangedMetadata() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = generator.generateKeyPair()
        val createdAt = Instant.parse("2026-10-24T12:00:00Z").toString()
        val payloadHash = AuditIntegrityChain.sha256Hex("{\"event_count\":3}")
        val chainHead = records.last().recordSha256
        val keyFingerprint = AuditIntegrityChain.sha256Hex(keyPair.public.encoded)
        val signedBytes = AuditIntegrityChain.checkpointSigningBytes(
            createdAt, payloadHash, chainHead, records.size, keyFingerprint
        )
        val signer = Signature.getInstance(AuditIntegrityChain.CHECKPOINT_SIGNATURE_ALGORITHM)
        signer.initSign(keyPair.private)
        signer.update(signedBytes)
        val signature = Base64.getEncoder().encodeToString(signer.sign())

        assertTrue(AuditIntegrityChain.verifySignature(keyPair.public, signedBytes, signature))
        val changedBytes = AuditIntegrityChain.checkpointSigningBytes(
            createdAt, payloadHash, chainHead, records.size - 1, keyFingerprint
        )
        assertFalse(AuditIntegrityChain.verifySignature(keyPair.public, changedBytes, signature))
    }
}
