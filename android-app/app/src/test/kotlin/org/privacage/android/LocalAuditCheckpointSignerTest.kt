package org.privacage.android

import java.io.File
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalAuditCheckpointSignerTest {
    private fun sharedCheckpoint(): String {
        val repositoryRoot = System.getProperty("privacage.repo-root")
            ?: error("The test must receive the repository root from Gradle.")
        return File(repositoryRoot, "shared/audit/test-vectors/checkpoint-v1.json")
            .readText(Charsets.UTF_8)
    }

    @Test
    fun verifiesTheSharedCheckpointVectorUsedByRustAndTheWebVerifier() {
        val result = LocalAuditCheckpointSigner.verify(sharedCheckpoint())

        assertTrue(result.signatureValid)
        assertTrue(result.payloadHashValid)
        assertTrue(result.chainValid)
        assertFalse(result.signerMatchesThisInstallation)
        assertEquals(1, result.eventCount)
        assertEquals("2026-10-24T10:01:00Z", result.createdAt)
        assertEquals(
            "11086649cd3e5d1892200a4200b165bbea5c9f9b47ca83792d4f9a1ef0dc8921",
            result.signerPublicKeySha256
        )
    }

    private fun sharedVector(name: String): String {
        val repositoryRoot = System.getProperty("privacage.repo-root")
            ?: error("The test must receive the repository root from Gradle.")
        return File(repositoryRoot, "shared/audit/test-vectors/$name").readText(Charsets.UTF_8)
    }

    @Test
    fun verifiesSharedEmptyAndMultiEventVectors() {
        val empty = LocalAuditCheckpointSigner.verify(sharedVector("checkpoint-v1-empty.json"))
        assertTrue(empty.signatureValid)
        assertTrue(empty.payloadHashValid)
        assertTrue(empty.chainValid)
        assertEquals(0, empty.eventCount)

        val multi = LocalAuditCheckpointSigner.verify(sharedVector("checkpoint-v1-multi-event.json"))
        assertTrue(multi.signatureValid)
        assertTrue(multi.payloadHashValid)
        assertTrue(multi.chainValid)
        assertEquals(2, multi.eventCount)
        val sameMulti = sharedVector("checkpoint-v1-multi-event.json")
        val comparison = LocalAuditCheckpointSigner.compare(sameMulti, sameMulti)
        assertEquals("same-chain", comparison.relationship)
        assertEquals(2, comparison.sharedPrefixEvents)
        assertEquals(0, comparison.firstEventsAfterSharedPrefix)
        assertEquals(0, comparison.secondEventsAfterSharedPrefix)
    }

    @Test
    fun detectsTheSamePayloadTamperingMutationAsTheOtherVerifiers() {
        val modifiedCheckpoint = sharedCheckpoint().replace("[REDACTED]", "private.example")
        val result = LocalAuditCheckpointSigner.verify(modifiedCheckpoint)

        // The signature covers the unchanged signed metadata. The payload digest and chain
        // independently expose the modification to the embedded snapshot.
        assertTrue(result.signatureValid)
        assertFalse(result.payloadHashValid)
        assertFalse(result.chainValid)
    }

    @Test
    fun rejectsDuplicateCheckpointKeysIncludingEscapedEquivalentKeys() {
        val source = sharedCheckpoint()
        val duplicateKey = source.replace(
            "\"format\": \"privacage-audit-checkpoint\",",
            "\"format\": \"privacage-audit-checkpoint\",\n  \"fo\\u0072mat\": \"privacage-audit-checkpoint\","
        )

        assertThrows(IOException::class.java) {
            LocalAuditCheckpointSigner.verify(duplicateKey)
        }
    }

    @Test
    fun rejectsDuplicateKeysInsideTheEmbeddedPayloadBeforeDigestEvaluation() {
        val source = sharedCheckpoint()
        val payloadPrefix = "\\\"schema_version\\\":1,\\\"source\\\":"
        val duplicatePrefix = "\\\"schema_version\\\":1,\\\"schema_version\\\":1,\\\"source\\\":"
        val duplicatePayloadKey = source.replace(payloadPrefix, duplicatePrefix)

        assertTrue("The test mutation must change the shared payload.", duplicatePayloadKey != source)
        assertThrows(IOException::class.java) {
            LocalAuditCheckpointSigner.verify(duplicatePayloadKey)
        }
    }


    @Test
    fun comparesAnIdenticalSharedCheckpointWithoutExposingEvents() {
        val checkpoint = sharedCheckpoint()
        val result = LocalAuditCheckpointSigner.compare(checkpoint, checkpoint)

        assertEquals("same-chain", result.relationship)
        assertEquals(1, result.sharedPrefixEvents)
        assertEquals(0, result.firstEventsAfterSharedPrefix)
        assertEquals(0, result.secondEventsAfterSharedPrefix)
        assertEquals(1, result.eventCountA)
        assertEquals(1, result.eventCountB)
    }

    @Test
    fun refusesToCompareCheckpointWithTamperedPayload() {
        val checkpointA = sharedCheckpoint()
        val checkpointB = checkpointA.replace("[REDACTED]", "private.example")

        assertThrows(IOException::class.java) {
            LocalAuditCheckpointSigner.compare(checkpointA, checkpointB)
        }
    }


}
