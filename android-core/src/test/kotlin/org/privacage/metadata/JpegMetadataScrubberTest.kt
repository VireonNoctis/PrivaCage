package org.privacage.metadata

import java.io.File
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class JpegMetadataScrubberTest {
    @Test
    fun removesCommonMetadataWithoutChangingScanData() {
        val soi = bytes(0xFF, 0xD8)
        val app0 = segment(0xE0, bytes(0x4A, 0x46, 0x49, 0x46, 0x00, 0x01))
        val exif = segment(0xE1, "Exif\u0000\u0000GPS:fake".toByteArray())
        val iptc = segment(0xED, "Photoshop IPTC".toByteArray())
        val comment = segment(0xFE, "private comment".toByteArray())
        val sos = segment(0xDA, bytes(0x01, 0x01, 0x00, 0x00, 0x3F, 0x00))
        val scan = bytes(0x11, 0xFF, 0x00, 0x22, 0xFF, 0xD0, 0x33)
        val eoi = bytes(0xFF, 0xD9)
        val inputBytes = soi + app0 + exif + iptc + comment + sos + scan + eoi
        val expected = soi + app0 + sos + scan + eoi
        val input = File.createTempFile("pcage-jpeg-in-", ".jpg")
        val output = File.createTempFile("pcage-jpeg-out-", ".jpg")
        try {
            input.writeBytes(inputBytes)
            val result = JpegMetadataScrubber.scrub(input, output)
            assertContentEquals(expected, output.readBytes())
            assertEquals(3, result.metadataSegmentsRemoved)
            assertEquals((exif.size + iptc.size + comment.size).toLong(), result.metadataBytesRemoved)
            assertEquals(expected.size.toLong(), result.outputBytesWritten)
        } finally { input.delete(); output.delete() }
    }

    @Test
    fun removesMetadataBetweenProgressiveScans() {
        val firstScan = segment(0xDA, bytes(0x01, 0x01, 0x00, 0x00, 0x3F, 0x00))
        val secondScan = segment(0xDA, bytes(0x01, 0x01, 0x00, 0x01, 0x3F, 0x00))
        val metadata = segment(0xE1, "Exif\u0000GPS".toByteArray())
        val inputBytes = bytes(0xFF, 0xD8) + firstScan + bytes(0x11, 0x22) + metadata +
            secondScan + bytes(0x33, 0xFF, 0xD9)
        val expected = bytes(0xFF, 0xD8) + firstScan + bytes(0x11, 0x22) +
            secondScan + bytes(0x33, 0xFF, 0xD9)
        val input = File.createTempFile("pcage-jpeg-in-", ".jpg")
        val output = File.createTempFile("pcage-jpeg-out-", ".jpg")
        try {
            input.writeBytes(inputBytes)
            val result = JpegMetadataScrubber.scrub(input, output)
            assertContentEquals(expected, output.readBytes())
            assertEquals(1, result.metadataSegmentsRemoved)
        } finally { input.delete(); output.delete() }
    }

    @Test
    fun rejectsTruncatedSegmentsAndNonJpegFiles() {
        val input = File.createTempFile("pcage-jpeg-in-", ".jpg")
        val output = File.createTempFile("pcage-jpeg-out-", ".jpg")
        try {
            input.writeBytes(bytes(0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10, 0x01))
            assertFailsWith<IOException> { JpegMetadataScrubber.scrub(input, output) }
            input.writeText("not a jpeg")
            assertFailsWith<IOException> { JpegMetadataScrubber.scrub(input, output) }
        } finally { input.delete(); output.delete() }
    }

    @Test
    fun enforcesInputSizeLimit() {
        val input = File.createTempFile("pcage-jpeg-in-", ".jpg")
        val output = File.createTempFile("pcage-jpeg-out-", ".jpg")
        try {
            input.writeBytes(bytes(0xFF, 0xD8, 0xFF, 0xD9))
            assertFailsWith<IOException> { JpegMetadataScrubber.scrub(input, output, maxBytes = 3) }
        } finally { input.delete(); output.delete() }
    }

    private fun segment(marker: Int, payload: ByteArray): ByteArray {
        val length = payload.size + 2
        return bytes(0xFF, marker, length ushr 8, length and 0xFF) + payload
    }
    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }
}
