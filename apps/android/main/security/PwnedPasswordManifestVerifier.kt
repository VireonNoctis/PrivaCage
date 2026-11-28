package org.privacage.security

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.time.LocalDate
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException
import org.json.JSONObject
import org.privacage.android.StrictJsonKeyScanner

internal data class PwnedPasswordManifestRange(
    val prefix: String,
    val sizeBytes: Int,
    val recordCount: ULong,
    val sha256: String
)

internal data class VerifiedPwnedPasswordManifest(
    val snapshotDate: LocalDate,
    val selectedRange: PwnedPasswordManifestRange
)

/**
 * Verifies the complete bounded JSONL inventory and returns one selected range.
 *
 * The expected manifest SHA-256 must be retained independently. This authenticates
 * the exact local manifest bytes only; it is not a HIBP publisher signature.
 */
internal object PwnedPasswordManifestVerifier {
    const val COMPLETE_RANGE_COUNT = 1 shl 20
    const val MAX_MANIFEST_BYTES = 128 * 1024 * 1024
    private const val MAX_LINE_BYTES = 4 * 1024
    private const val MAX_RANGE_FILE_BYTES = 4 * 1024 * 1024
    private const val MAX_RANGE_RECORDS = 100_000uL
    private const val MAX_DATASET_BYTES = 256L shl 30

    private val headerFields = setOf(
        "type", "version", "source", "hash", "snapshot_date",
        "generated_at", "range_count", "total_bytes", "total_records"
    )
    private val entryFields = setOf("prefix", "size", "records", "sha256")
    private val unsignedInteger = Regex("(?:0|[1-9][0-9]*)")
    private val sha256Pattern = Regex("[0-9A-F]{64}")
    private val expectedDigestPattern = Regex("[0-9A-Fa-f]{64}")

    @Throws(IOException::class)
    fun verify(
        manifestPath: Path,
        expectedSha256: String,
        selectedPrefix: String,
        today: LocalDate = LocalDate.now(),
        expectedRangeCount: Int = COMPLETE_RANGE_COUNT
    ): VerifiedPwnedPasswordManifest {
        ensurePwnedPasswordWorkActive()
        require(expectedRangeCount in 1..COMPLETE_RANGE_COUNT) {
            "Expected range count is outside the supported prefix space."
        }
        require(selectedPrefix.matches(Regex("[0-9A-F]{5}"))) {
            "Selected prefix must be five uppercase hexadecimal characters."
        }
        require(expectedDigestPattern.matches(expectedSha256)) {
            "Expected manifest SHA-256 must contain exactly 64 hexadecimal characters."
        }
        val selectedIndex = selectedPrefix.toInt(16)
        if (selectedIndex >= expectedRangeCount) {
            throw IOException("Selected prefix is outside the manifest inventory.")
        }
        if (!Files.isRegularFile(manifestPath, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("Manifest must be a regular non-symbolic file.")
        }

        Files.newByteChannel(
            manifestPath,
            StandardOpenOption.READ,
            LinkOption.NOFOLLOW_LINKS
        ).use { channel ->
            val capturedSize = channel.size()
            if (capturedSize <= 0L || capturedSize > MAX_MANIFEST_BYTES) {
                throw IOException("Manifest is empty or exceeds the 128 MiB input limit.")
            }
            val reader = ManifestLineReader(channel, capturedSize)
            val headerLine = reader.readLine()
                ?: throw IOException("Manifest header is missing.")
            val header = parseObject(headerLine, "Pwned Passwords manifest header", headerFields)

            if (stringValue(header, "type") != "pcage-pwned-password-ranges" ||
                unsignedValue(header, "version") != 1uL ||
                stringValue(header, "source") != "HIBP-Pwned-Passwords" ||
                stringValue(header, "hash") != "SHA-1"
            ) {
                throw IOException("Manifest header does not describe the supported Pwned Passwords format.")
            }

            val rangeCount = unsignedValue(header, "range_count")
            if (rangeCount != expectedRangeCount.toULong()) {
                throw IOException("Manifest does not contain the expected complete prefix inventory.")
            }
            val snapshotDate = try {
                LocalDate.parse(stringValue(header, "snapshot_date"))
            } catch (exception: DateTimeParseException) {
                throw IOException("Manifest snapshot date is invalid.", exception)
            }
            if (snapshotDate.isAfter(today)) {
                throw IOException("Manifest snapshot date is in the future.")
            }
            try {
                OffsetDateTime.parse(stringValue(header, "generated_at"))
            } catch (exception: DateTimeParseException) {
                throw IOException("Manifest generation timestamp is invalid.", exception)
            }

            val declaredTotalBytes = unsignedValue(header, "total_bytes")
            if (declaredTotalBytes > MAX_DATASET_BYTES.toULong()) {
                throw IOException("Manifest total byte count exceeds the supported dataset limit.")
            }
            val declaredTotalRecords = unsignedValue(header, "total_records")

            var totalBytes = 0uL
            var totalRecords = 0uL
            var selected: PwnedPasswordManifestRange? = null

            for (index in 0 until expectedRangeCount) {
                ensurePwnedPasswordWorkActive()
                val line = reader.readLine()
                    ?: throw IOException("Manifest entry " + prefixFor(index) + " is missing.")
                val entryObject = parseObject(line, "Pwned Passwords manifest entry", entryFields)
                val expectedPrefix = prefixFor(index)
                val prefix = stringValue(entryObject, "prefix")
                if (prefix != expectedPrefix) {
                    throw IOException("Manifest prefix inventory is missing, duplicated, or out of order.")
                }

                val size = unsignedValue(entryObject, "size")
                val records = unsignedValue(entryObject, "records")
                val digest = stringValue(entryObject, "sha256")
                if (size > MAX_RANGE_FILE_BYTES.toULong() ||
                    records > MAX_RANGE_RECORDS ||
                    ((size == 0uL) != (records == 0uL)) ||
                    !sha256Pattern.matches(digest)
                ) {
                    throw IOException("Manifest entry " + expectedPrefix + " has invalid bounds or fields.")
                }
                if (totalBytes > MAX_DATASET_BYTES.toULong() - size ||
                    ULong.MAX_VALUE - totalRecords < records
                ) {
                    throw IOException("Manifest totals exceed supported limits.")
                }
                totalBytes += size
                totalRecords += records

                if (prefix == selectedPrefix) {
                    selected = PwnedPasswordManifestRange(
                        prefix = prefix,
                        sizeBytes = size.toInt(),
                        recordCount = records,
                        sha256 = digest
                    )
                }
            }

            if (reader.readLine() != null) {
                throw IOException("Manifest contains trailing entries or data.")
            }
            val actualDigest = reader.finishDigest()
            val expectedDigestBytes = decodeDigest(expectedSha256)
            if (!MessageDigest.isEqual(actualDigest, expectedDigestBytes)) {
                throw IOException("Manifest SHA-256 does not match the independently retained digest.")
            }
            if (totalBytes != declaredTotalBytes || totalRecords != declaredTotalRecords || totalRecords == 0uL) {
                throw IOException("Manifest aggregate totals do not match its entries.")
            }
            return VerifiedPwnedPasswordManifest(
                snapshotDate = snapshotDate,
                selectedRange = selected ?: throw IOException("Selected range is absent from the manifest.")
            )
        }
    }

    private fun parseObject(lineBytes: ByteArray, label: String, expectedFields: Set<String>): JSONObject {
        var length = lineBytes.size
        if (length > 0 && lineBytes[length - 1] == '\r'.code.toByte()) length -= 1
        if (length == 0) throw IOException(label + " is empty.")
        for (index in 0 until length) {
            val value = lineBytes[index].toInt() and 0xff
            if (value >= 0x80 || (value < 0x20 && value != '\t'.code)) {
                throw IOException(label + " must contain ASCII JSON only.")
            }
        }
        val source = String(lineBytes, 0, length, StandardCharsets.US_ASCII)
        StrictJsonKeyScanner.validate(source, label)
        val parsed = try {
            JSONObject(source)
        } catch (exception: Exception) {
            throw IOException(label + " is malformed.", exception)
        }
        val actualFields = parsed.keys().asSequence().toSet()
        if (actualFields != expectedFields) {
            throw IOException(label + " has missing or unknown fields.")
        }
        return parsed
    }

    private fun stringValue(objectValue: JSONObject, key: String): String {
        return objectValue.get(key) as? String
            ?: throw IOException("Manifest field " + key + " must be a string.")
    }

    private fun unsignedValue(objectValue: JSONObject, key: String): ULong {
        val value = objectValue.get(key)
        if (value !is Number) throw IOException("Manifest field " + key + " must be an unsigned integer.")
        val text = value.toString()
        if (!unsignedInteger.matches(text)) {
            throw IOException("Manifest field " + key + " is not a canonical unsigned integer.")
        }
        return text.toULongOrNull()
            ?: throw IOException("Manifest field " + key + " exceeds the unsigned 64-bit limit.")
    }

    private fun prefixFor(index: Int): String = index.toString(16).uppercase().padStart(5, '0')

    private fun decodeDigest(value: String): ByteArray {
        return ByteArray(32) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private class ManifestLineReader(
        private val channel: SeekableByteChannel,
        private val capturedSize: Long
    ) {
        private val digest = MessageDigest.getInstance("SHA-256")
        private val buffer = ByteBuffer.allocate(8 * 1024).apply { limit(0) }
        private var unreadBytes = capturedSize

        @Throws(IOException::class)
        fun readLine(): ByteArray? {
            val line = ByteArrayOutputStream()
            while (true) {
                ensurePwnedPasswordWorkActive()
                if (!buffer.hasRemaining()) {
                    if (unreadBytes == 0L) {
                        if (line.size() == 0) return null
                        throw IOException("Manifest final record is not newline terminated.")
                    }
                    buffer.clear()
                    buffer.limit(minOf(buffer.capacity().toLong(), unreadBytes).toInt())
                    val read = channel.read(buffer)
                    if (read < 0) throw IOException("Manifest was truncated while being read.")
                    if (read == 0) throw IOException("Manifest provider returned a zero-length read.")
                    digest.update(buffer.array(), 0, read)
                    unreadBytes -= read
                    buffer.flip()
                }

                val value = buffer.get().toInt() and 0xff
                if (value == '\n'.code) return line.toByteArray()
                if (line.size() >= MAX_LINE_BYTES) {
                    throw IOException("Manifest JSONL record exceeds the 4096-byte line limit.")
                }
                line.write(value)
            }
        }

        @Throws(IOException::class)
        fun finishDigest(): ByteArray {
            if (unreadBytes != 0L || buffer.hasRemaining()) {
                throw IOException("Manifest was not fully consumed.")
            }
            if (channel.size() != capturedSize) {
                throw IOException("Manifest size changed while it was being verified.")
            }
            return digest.digest()
        }
    }
}
