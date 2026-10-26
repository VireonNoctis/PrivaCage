package org.privacage.android

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
}
