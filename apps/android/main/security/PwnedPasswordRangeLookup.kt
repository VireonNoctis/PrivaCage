package org.privacage.security

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.channels.SeekableByteChannel
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.time.LocalDate

enum class PwnedPasswordExposureStatus {
    FOUND,
    NOT_FOUND_IN_SNAPSHOT
}

data class PwnedPasswordExposureResult(
    val status: PwnedPasswordExposureStatus,
    val occurrences: ULong?,
    val snapshotDate: LocalDate
) {
    init {
        require((status == PwnedPasswordExposureStatus.FOUND) == (occurrences != null))
        require(occurrences == null || occurrences > 0uL)
    }
}

/**
 * Local-only reader for the official Have I Been Pwned Pwned Passwords SHA-1
 * directory format. Each PREFIX.txt contains 35-character suffix records; the
 * five-character prefix is represented by the filename. SHA-1 is used only for
 * corpus compatibility.
 *
 * The caller must pass a dedicated CharArray: checkAndClear consumes and clears it.
 * The snapshot date is caller-supplied and is not authenticated by this core.
 */
object PwnedPasswordRangeLookup {
    const val MAX_PASSWORD_CHARS = 4_096
    const val MAX_RANGE_FILE_BYTES = 4 * 1024 * 1024
    const val MAX_RANGE_LINES = 100_000
    const val DATASET_SOURCE_URL = "https://haveibeenpwned.com/Passwords"

    private const val HASH_HEX_LENGTH = 40
    private const val PREFIX_HEX_LENGTH = 5
    private const val HASH_SUFFIX_HEX_LENGTH = HASH_HEX_LENGTH - PREFIX_HEX_LENGTH
    private const val MAX_RANGE_RECORD_BYTES = HASH_SUFFIX_HEX_LENGTH + 1 + 20

    @Throws(IOException::class)
    fun checkAndClear(
        password: CharArray,
        rangeDirectory: Path,
        snapshotDate: LocalDate,
        today: LocalDate = LocalDate.now()
    ): PwnedPasswordExposureResult = checkAndClearInternal(
        password, rangeDirectory, snapshotDate, null, null, today,
        PwnedPasswordManifestVerifier.COMPLETE_RANGE_COUNT, null
    )

    /**
     * Requires a complete manifest by default and an expected digest retained separately.
     * The test-only range-count override exists for the shared four-prefix fixture.
     */
    @Throws(IOException::class)
    internal fun checkAndClearWithManifest(
        password: CharArray,
        rangeDirectory: Path,
        manifestPath: Path,
        expectedManifestSha256: String,
        today: LocalDate = LocalDate.now(),
        expectedRangeCount: Int = PwnedPasswordManifestVerifier.COMPLETE_RANGE_COUNT,
        selectedRangePrefix: String? = null
    ): PwnedPasswordExposureResult = checkAndClearInternal(
        password, rangeDirectory, null, manifestPath, expectedManifestSha256, today, expectedRangeCount,
        selectedRangePrefix
    )

    private fun checkAndClearInternal(
        password: CharArray,
        rangeDirectory: Path,
        snapshotDate: LocalDate?,
        manifestPath: Path?,
        expectedManifestSha256: String?,
        today: LocalDate,
        expectedRangeCount: Int,
        selectedRangePrefix: String?
    ): PwnedPasswordExposureResult {
        try {
            require(password.isNotEmpty()) { "Password must not be empty." }
            require(password.size <= MAX_PASSWORD_CHARS) {
                "Password exceeds the $MAX_PASSWORD_CHARS-character processing limit."
            }
            require(manifestPath != null || snapshotDate != null) {
                "A snapshot date or verified manifest is required."
            }
            require((manifestPath == null) == (expectedManifestSha256 == null)) {
                "Manifest path and independently retained digest must be supplied together."
            }
            require(expectedRangeCount in 1..PwnedPasswordManifestVerifier.COMPLETE_RANGE_COUNT) {
                "Expected range count is outside the supported prefix space."
            }
            selectedRangePrefix?.let {
                require(it.matches(Regex("[0-9A-F]{5}"))) {
                    "Selected range prefix must be five uppercase hexadecimal characters."
                }
            }
            snapshotDate?.let {
                require(!it.isAfter(today)) { "Dataset snapshot date cannot be in the future." }
            }
            require(Files.isDirectory(rangeDirectory, LinkOption.NOFOLLOW_LINKS)) {
                "Selected Pwned Passwords range path is not a local directory."
            }

            val encoded = try {
                StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(password))
            } catch (exception: CharacterCodingException) {
                throw IllegalArgumentException("Password contains invalid Unicode.", exception)
            }

            try {
                val passwordBytes = ByteArray(encoded.remaining())
                try {
                    encoded.get(passwordBytes)
                    val hashBytes = MessageDigest.getInstance("SHA-1").digest(passwordBytes)
                    try {
                        val hashHex = toUpperHex(hashBytes)
                        val prefix = hashHex.substring(0, PREFIX_HEX_LENGTH)
                        val targetSuffix = hashHex.substring(PREFIX_HEX_LENGTH)
                        password.fill('\u0000')
                        if (selectedRangePrefix != null && selectedRangePrefix != prefix) {
                            throw IOException(
                                "Selected range file " + selectedRangePrefix + ".txt does not match required prefix " + prefix + "."
                            )
                        }

                        val verifiedManifest = manifestPath?.let {
                            PwnedPasswordManifestVerifier.verify(
                                it,
                                expectedManifestSha256!!,
                                prefix,
                                today,
                                expectedRangeCount
                            )
                        }
                        val effectiveSnapshotDate = verifiedManifest?.snapshotDate ?: snapshotDate!!
                        val rangeFile = rangeDirectory.resolve("$prefix.txt")
                        val occurrences = findOccurrences(
                            rangeFile,
                            prefix,
                            targetSuffix,
                            verifiedManifest?.selectedRange
                        )
                        return PwnedPasswordExposureResult(
                            status = if (occurrences == null) {
                                PwnedPasswordExposureStatus.NOT_FOUND_IN_SNAPSHOT
                            } else {
                                PwnedPasswordExposureStatus.FOUND
                            },
                            occurrences = occurrences,
                            snapshotDate = effectiveSnapshotDate
                        )
                    } finally {
                        hashBytes.fill(0)
                    }
                } finally {
                    passwordBytes.fill(0)
                }
            } finally {
                clearBuffer(encoded)
            }
        } finally {
            password.fill('\u0000')
        }
    }

    private fun findOccurrences(
        rangeFile: Path,
        prefix: String,
        targetSuffix: String,
        expectedEntry: PwnedPasswordManifestRange?
    ): ULong? {
        if (!Files.exists(rangeFile, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException(
                "Required Pwned Passwords range file $prefix.txt is missing; the local dataset may be incomplete."
            )
        }
        if (!Files.isRegularFile(rangeFile, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("Required Pwned Passwords range file is not a regular non-symbolic file.")
        }

        Files.newByteChannel(
            rangeFile,
            StandardOpenOption.READ,
            LinkOption.NOFOLLOW_LINKS
        ).use { channel ->
            val rangeBytes = channel.size()
            if (rangeBytes > MAX_RANGE_FILE_BYTES) {
                throw IOException(
                    "Pwned Passwords range file exceeds the $MAX_RANGE_FILE_BYTES-byte safety limit."
                )
            }
            if (expectedEntry == null && rangeBytes < (HASH_SUFFIX_HEX_LENGTH + 2).toLong()) {
                throw IOException(
                    "Pwned Passwords range file is empty or shorter than one complete record; result unavailable."
                )
            }
            if (expectedEntry != null &&
                (expectedEntry.prefix != prefix || expectedEntry.sizeBytes.toLong() != rangeBytes)
            ) {
                throw IOException("Pwned Passwords range size does not match its verified manifest entry.")
            }
            return parseRange(channel, rangeBytes, targetSuffix, expectedEntry)
        }
    }

    private fun parseRange(
        channel: SeekableByteChannel,
        capturedSize: Long,
        targetSuffix: String,
        expectedEntry: PwnedPasswordManifestRange?
    ): ULong? {
        var previousSuffix: String? = null
        var matchCount: ULong? = null
        var lineCount = 0
        var lineLength = 0
        var remainingBytes = capturedSize
        val lineBuffer = ByteArray(MAX_RANGE_RECORD_BYTES + 1)
        val inputBuffer = ByteBuffer.allocate(8 * 1024).apply { limit(0) }
        val digest = if (expectedEntry != null) MessageDigest.getInstance("SHA-256") else null

        fun processLine() {
            lineCount += 1
            if (lineCount > MAX_RANGE_LINES) {
                throw IOException(
                    "Pwned Passwords range file exceeds the $MAX_RANGE_LINES-line safety limit."
                )
            }

            var recordLength = lineLength
            if (recordLength > 0 && lineBuffer[recordLength - 1] == '\r'.code.toByte()) {
                recordLength -= 1
            }
            if (recordLength !in (HASH_SUFFIX_HEX_LENGTH + 2)..MAX_RANGE_RECORD_BYTES) {
                throw IOException("Pwned Passwords range file has an invalid record at line $lineCount.")
            }

            val line = String(lineBuffer, 0, recordLength, StandardCharsets.US_ASCII)
            if (line[HASH_SUFFIX_HEX_LENGTH] != ':') {
                throw IOException("Pwned Passwords range file has an invalid record at line $lineCount.")
            }

            val suffix = line.substring(0, HASH_SUFFIX_HEX_LENGTH)
            if (suffix.any { it !in '0'..'9' && it !in 'A'..'F' }) {
                throw IOException("Pwned Passwords range file has an invalid suffix at line $lineCount.")
            }
            previousSuffix?.let {
                if (suffix <= it) {
                    throw IOException("Pwned Passwords range file is not strictly sorted at line $lineCount.")
                }
            }

            val countText = line.substring(HASH_SUFFIX_HEX_LENGTH + 1)
            if (countText.length !in 1..20 || countText.any { it !in '0'..'9' }) {
                throw IOException("Pwned Passwords range file has an invalid count at line $lineCount.")
            }
            val count = countText.toULongOrNull()
                ?: throw IOException("Pwned Passwords range count is out of range at line $lineCount.")
            if (count == 0uL || count.toString() != countText) {
                throw IOException("Pwned Passwords range count is not canonical at line $lineCount.")
            }

            if (suffix == targetSuffix) matchCount = count
            previousSuffix = suffix
        }

        while (remainingBytes > 0) {
            if (!inputBuffer.hasRemaining()) {
                while (true) {
                    inputBuffer.clear()
                    inputBuffer.limit(minOf(inputBuffer.capacity().toLong(), remainingBytes).toInt())
                    val read = channel.read(inputBuffer)
                    if (read < 0) {
                        throw IOException("Pwned Passwords range file was truncated while it was being read.")
                    }
                    if (read == 0) throw IOException("Pwned Passwords range provider returned a zero-length read.")
                    digest?.update(inputBuffer.array(), 0, read)
                    inputBuffer.flip()
                    break
                }
            }

            val next = inputBuffer.get().toInt() and 0xff
            remainingBytes -= 1
            if (next == '\n'.code) {
                processLine()
                lineLength = 0
            } else {
                if (lineLength >= lineBuffer.size) {
                    throw IOException(
                        "Pwned Passwords range record exceeds $MAX_RANGE_RECORD_BYTES bytes."
                    )
                }
                lineBuffer[lineLength] = next.toByte()
                lineLength += 1
            }
        }

        if (lineLength > 0) processLine()
        if (expectedEntry != null) {
            if (lineCount.toULong() != expectedEntry.recordCount) {
                throw IOException("Pwned Passwords range record count does not match its manifest entry.")
            }
            val actualDigest = toUpperHex(digest!!.digest())
            if (actualDigest != expectedEntry.sha256) {
                throw IOException("Pwned Passwords range SHA-256 does not match its manifest entry.")
            }
            if (channel.size() != capturedSize) {
                throw IOException("Pwned Passwords range size changed while it was being checked.")
            }
        }
        return matchCount
    }

    private fun toUpperHex(bytes: ByteArray): String {
        val digits = "0123456789ABCDEF"
        return buildString(bytes.size * 2) {
            bytes.forEach { byte ->
                val value = byte.toInt() and 0xff
                append(digits[value ushr 4])
                append(digits[value and 0x0f])
            }
        }
    }

    private fun clearBuffer(buffer: ByteBuffer) {
        val duplicate = buffer.duplicate()
        duplicate.clear()
        while (duplicate.hasRemaining()) duplicate.put(0.toByte())
    }
}
