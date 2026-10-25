package org.privacage.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class TrackerSignatureCatalogSchemaTest {
    @Test
    fun acceptsOnlyIntegerSchemaVersionOne() {
        assertTrue(TrackerSignatureCatalog.isSupportedSchemaVersion(1))
    }

    @Test
    fun rejectsCoercedOrNonIntegralSchemaVersions() {
        val unsupportedValues = listOf(
            1.0,
            1.5,
            "1",
            true,
            2,
            1L,
            null
        )

        for (value in unsupportedValues) {
            assertFalse("Expected $value to be rejected", TrackerSignatureCatalog.isSupportedSchemaVersion(value))
        }
    }

    @Test
    fun acceptsAnInitialSignedReleaseFloor() {
        val release = verifiedRelease(sequence = 1L, manifestSha256 = "a".repeat(64))
        TrackerSignatureCatalog.ensureReleaseFloor(release, 0L, null)
    }

    @Test(expected = IOException::class)
    fun rejectsReleaseSequenceRollback() {
        TrackerSignatureCatalog.ensureReleaseFloor(
            verifiedRelease(sequence = 1L, manifestSha256 = "a".repeat(64)),
            2L,
            "b".repeat(64)
        )
    }

    @Test(expected = IOException::class)
    fun rejectsDifferentManifestAtTheSameSequence() {
        TrackerSignatureCatalog.ensureReleaseFloor(
            verifiedRelease(sequence = 2L, manifestSha256 = "a".repeat(64)),
            2L,
            "b".repeat(64)
        )
    }

    @Test(expected = IOException::class)
    fun rejectsAnIncompleteStoredFloor() {
        TrackerSignatureCatalog.ensureReleaseFloor(
            verifiedRelease(sequence = 2L, manifestSha256 = "a".repeat(64)),
            1L,
            null
        )
    }

    private fun verifiedRelease(sequence: Long, manifestSha256: String) = VerifiedTrackerRelease(
        sequence = sequence,
        catalogSha256 = "c".repeat(64),
        manifestSha256 = manifestSha256,
        createdAt = "2026-10-25",
        expiresAt = "2027-10-25"
    )

}
