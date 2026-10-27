package org.privacage.android

import java.io.IOException
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeMetadataResponseTest {
    @Test
    fun decodesExactSuccessSchemaAndCounters() {
        val report = decodeNativeMetadataResponse(successResponse().toString())
        assertEquals("png", report.format)
        assertEquals(100L, report.inputBytes)
        assertEquals(90L, report.outputBytes)
        assertEquals(1L, report.metadataSegmentsRemoved)
        assertEquals(10L, report.metadataBytesRemoved)
        assertEquals(1L, report.pngExifChunksRemoved)
        assertEquals(listOf("Unknown ancillary chunks are retained."), report.warnings)
    }

    @Test
    fun rejectsDuplicateKeysUnknownFieldsAndCoercibleOkValues() {
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse("""{"ok":true,"ok":false,"report":{}}""")
        }
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse("""{"ok":"true","report":{}}""")
        }
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse(successResponse().put("debug", true).toString())
        }
    }

    @Test
    fun rejectsStringFractionalNegativeAndInconsistentCounters() {
        val stringCount = successResponse()
        stringCount.getJSONObject("report").put("input_bytes", "100")
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse(stringCount.toString())
        }

        val fractionalCount = successResponse()
        fractionalCount.getJSONObject("report").put("output_bytes", 90.5)
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse(fractionalCount.toString())
        }

        val negativeCount = successResponse()
        negativeCount.getJSONObject("report").put("metadata_bytes_removed", -1)
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse(negativeCount.toString())
        }

        val inconsistent = successResponse()
        inconsistent.getJSONObject("report").put("jpeg_app1_segments_removed", 2)
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse(inconsistent.toString())
        }
    }

    @Test
    fun rejectsNonStringWarningsAndOversizedResponses() {
        val badWarnings = successResponse()
        badWarnings.getJSONObject("report").put("warnings", JSONArray().put(123))
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse(badWarnings.toString())
        }
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse(" ".repeat(64 * 1024 + 1))
        }
    }

    @Test
    fun surfacesNativeErrorOnlyWithExactStringSchema() {
        assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse("""{"ok":false,"error":123}""")
        }
        val exception = assertThrows(IOException::class.java) {
            decodeNativeMetadataResponse("""{"ok":false,"error":"Invalid image header"}""")
        }
        assertTrue(exception.message.orEmpty().contains("Invalid image header"))
    }

    private fun successResponse(): JSONObject {
        val report = JSONObject()
            .put("format", "png")
            .put("input_bytes", 100)
            .put("output_bytes", 90)
            .put("metadata_segments_removed", 1)
            .put("metadata_bytes_removed", 10)
            .put("jpeg_app1_segments_removed", 0)
            .put("jpeg_app13_segments_removed", 0)
            .put("jpeg_comment_segments_removed", 0)
            .put("png_exif_chunks_removed", 1)
            .put("png_text_chunks_removed", 0)
            .put("png_timestamp_chunks_removed", 0)
            .put("png_physical_chunks_removed", 0)
            .put("webp_exif_chunks_removed", 0)
            .put("webp_xmp_chunks_removed", 0)
            .put("warnings", JSONArray().put("Unknown ancillary chunks are retained."))
        return JSONObject().put("ok", true).put("report", report)
    }
}
