package org.privacage.android

import java.io.IOException
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class TrackerSignatureCatalogSchemaTest {
    @Test
    fun strictUtf8DecoderAcceptsValidUnicode() {
        val json = """{"name":"😀"}""".toByteArray(Charsets.UTF_8)
        assertTrue(TrackerSignatureCatalog.decodeUtf8Strict(json).contains("😀"))
    }

    @Test
    fun strictUtf8DecoderRejectsMalformedBytes() {
        val malformed = byteArrayOf(0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff.toByte(), 0x22, 0x7d)
        assertThrows(IOException::class.java) {
            TrackerSignatureCatalog.decodeUtf8Strict(malformed)
        }
    }

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
