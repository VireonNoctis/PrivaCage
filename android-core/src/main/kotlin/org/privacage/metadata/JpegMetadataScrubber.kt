package org.privacage.metadata

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.PushbackInputStream

data class JpegScrubResult(
    val metadataSegmentsRemoved: Int,
    val metadataBytesRemoved: Long,
    val outputBytesWritten: Long
)

/**
 * Removes common identifying JPEG segments without decoding or recompressing image pixels:
 * APP1 (EXIF/XMP), APP13 (IPTC/Photoshop metadata), and COM comments.
 * Other APP segments are preserved, including ICC color profiles; this is not a universal scrubber.
 */
object JpegMetadataScrubber {
    private const val SOI = 0xD8
    private const val EOI = 0xD9
    private const val SOS = 0xDA
    private const val APP1 = 0xE1
    private const val APP13 = 0xED
    private const val COM = 0xFE
    private const val TEM = 0x01
    private const val RST0 = 0xD0
    private const val RST7 = 0xD7
    private const val MAX_MARKER_FILL = 32
    private const val DEFAULT_MAX_BYTES = 100L * 1024 * 1024

    fun scrub(inputFile: File, outputFile: File, maxBytes: Long = DEFAULT_MAX_BYTES): JpegScrubResult {
        require(inputFile.canonicalFile != outputFile.canonicalFile) { "Input and output files must differ" }
        require(maxBytes > 0) { "Maximum input size must be positive" }
        if (!inputFile.isFile || inputFile.length() !in 4..maxBytes) {
            throw IOException("JPEG must be a readable file within the configured size limit.")
        }
        if (outputFile.exists() && !outputFile.delete()) throw IOException("Could not replace the temporary output file.")

        var removedSegments = 0
        var removedBytes = 0L
        var outputBytes = 0L
        try {
            PushbackInputStream(BufferedInputStream(FileInputStream(inputFile)), MAX_MARKER_FILL + 2).use { input ->
                BufferedOutputStream(FileOutputStream(outputFile)).use { output ->
                    fun emitByte(value: Int) { output.write(value); outputBytes++ }
                    fun readRequired(context: String): Int {
                        val value = input.read()
                        if (value < 0) throw IOException("Truncated JPEG while reading " + context + ".")
                        return value
                    }
                    if (readRequired("JPEG signature") != 0xFF || readRequired("JPEG signature") != SOI) {
                        throw IOException("Selected file is not a JPEG image.")
                    }
                    emitByte(0xFF)
                    emitByte(SOI)

                    var sawScan = false
                    var sawEnd = false
                    var inEntropyData = false
                    while (!sawEnd) {
                        if (inEntropyData) {
                            outputBytes += copyEntropyUntilMarker(input, output)
                            inEntropyData = false
                        }
                        val prefix = ArrayList<Int>()
                        if (readRequired("marker prefix") != 0xFF) throw IOException("Invalid JPEG marker boundary.")
                        prefix.add(0xFF)
                        var code = readRequired("marker code")
                        while (code == 0xFF) {
                            prefix.add(code)
                            if (prefix.size > MAX_MARKER_FILL) throw IOException("Excessive JPEG marker fill bytes.")
                            code = readRequired("marker code")
                        }
                        if (code == 0x00) throw IOException("Unexpected stuffed byte outside JPEG scan data.")
                        if (code == EOI) {
                            prefix.forEach(::emitByte)
                            emitByte(code)
                            sawEnd = true
                            if (input.read() != -1) throw IOException("JPEG contains trailing data after its end marker.")
                            break
                        }
                        if (code == SOI || code == TEM || code in RST0..RST7) {
                            prefix.forEach(::emitByte)
                            emitByte(code)
                            continue
                        }
                        val lengthHigh = readRequired("segment length")
                        val lengthLow = readRequired("segment length")
                        val segmentLength = (lengthHigh shl 8) or lengthLow
                        if (segmentLength < 2) throw IOException("Invalid JPEG segment length.")
                        val payloadLength = segmentLength - 2
                        if (code == APP1 || code == APP13 || code == COM) {
                            skipExactly(input, payloadLength)
                            removedSegments++
                            removedBytes += prefix.size + 1L + 2L + payloadLength
                        } else {
                            prefix.forEach(::emitByte)
                            emitByte(code)
                            emitByte(lengthHigh)
                            emitByte(lengthLow)
                            outputBytes += copyExactly(input, output, payloadLength)
                        }
                        if (code == SOS) {
                            sawScan = true
                            inEntropyData = true
                        }
                    }
                    output.flush()
                    if (!sawScan || !sawEnd) throw IOException("JPEG has no complete image scan or end marker.")
                }
            }
            return JpegScrubResult(removedSegments, removedBytes, outputBytes)
        } catch (exception: Exception) {
            outputFile.delete()
            if (exception is IOException) throw exception
            throw IOException("Could not safely scrub JPEG metadata.", exception)
        }
    }

    private fun copyEntropyUntilMarker(input: PushbackInputStream, output: BufferedOutputStream): Long {
        var copied = 0L
        while (true) {
            val value = input.read()
            if (value < 0) throw IOException("JPEG scan data ended before an end marker.")
            if (value != 0xFF) {
                output.write(value)
                copied++
                continue
            }
            val markerBytes = ArrayList<Int>()
            markerBytes.add(0xFF)
            var code = input.read()
            if (code < 0) throw IOException("JPEG scan ends inside a marker.")
            while (code == 0xFF) {
                markerBytes.add(0xFF)
                if (markerBytes.size > MAX_MARKER_FILL) throw IOException("Excessive JPEG scan marker fill bytes.")
                code = input.read()
                if (code < 0) throw IOException("JPEG scan ends inside a marker.")
            }
            if (code == 0x00 || code in RST0..RST7) {
                markerBytes.add(code)
                markerBytes.forEach(output::write)
                copied += markerBytes.size
                continue
            }
            markerBytes.add(code)
            input.unread(ByteArray(markerBytes.size) { markerBytes[it].toByte() })
            return copied
        }
    }

    private fun copyExactly(input: PushbackInputStream, output: BufferedOutputStream, count: Int): Long {
        var remaining = count
        var copied = 0L
        val buffer = ByteArray(8_192)
        try {
            while (remaining > 0) {
                val read = input.read(buffer, 0, minOf(buffer.size, remaining))
                if (read < 0) throw IOException("Truncated JPEG segment payload.")
                if (read == 0) continue
                output.write(buffer, 0, read)
                remaining -= read
                copied += read
            }
        } finally { buffer.fill(0) }
        return copied
    }

    private fun skipExactly(input: PushbackInputStream, count: Int) {
        var remaining = count
        val buffer = ByteArray(8_192)
        try {
            while (remaining > 0) {
                val read = input.read(buffer, 0, minOf(buffer.size, remaining))
                if (read < 0) throw IOException("Truncated JPEG metadata segment.")
                if (read == 0) continue
                remaining -= read
            }
        } finally { buffer.fill(0) }
    }
}
