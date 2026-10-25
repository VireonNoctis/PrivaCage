package org.privacage.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

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
}
