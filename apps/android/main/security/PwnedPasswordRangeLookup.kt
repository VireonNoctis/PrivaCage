package org.privacage.security

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.time.LocalDate

enum class PwnedPasswordExposureStatus {
    FOUND,
    NOT_FOUND_IN_SNAPSHOT
}

data class PwnedPasswordExposureResult(
    val status: PwnedPasswordExposureStatus,
    val occurrences: Long?,
    val snapshotDate: LocalDate
) {
    init {
        require((status == PwnedPasswordExposureStatus.FOUND) == (occurrences != null))
        require(occurrences == null || occurrences > 0)
    }
}

/**
 * Local-only reader for the official Have I Been Pwned Pwned Passwords SHA-1
 * range-directory format. SHA-1 is used only for corpus compatibility.
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

    @Throws(IOException::class)
    fun checkAndClear(
        password: CharArray,
        rangeDirectory: Path,
        snapshotDate: LocalDate,
        today: LocalDate = LocalDate.now()
    ): PwnedPasswordExposureResult {
        try {
            require(password.isNotEmpty()) { "Password must not be empty." }
            require(password.size <= MAX_PASSWORD_CHARS) {
                "Password exceeds the $MAX_PASSWORD_CHARS-character processing limit."
            }
            require(!snapshotDate.isAfter(today)) {
                "Dataset snapshot date cannot be in the future."
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
                        password.fill('\u0000')

                        val rangeFile = rangeDirectory.resolve("$prefix.txt")
                        if (!Files.isRegularFile(rangeFile, LinkOption.NOFOLLOW_LINKS)) {
                            throw IOException(
                                "Required Pwned Passwords range file $prefix.txt is missing; " +
                                    "the result is unavailable because the local dataset may be incomplete."
                            )
                        }
                        val rangeBytes = Files.size(rangeFile)
                        if (rangeBytes < 42L) {
                            throw IOException(
                                "Pwned Passwords range file is empty or shorter than one complete record; result unavailable."
                            )
                        }
                        if (rangeBytes > MAX_RANGE_FILE_BYTES) {
                            throw IOException(
                                "Pwned Passwords range file exceeds the $MAX_RANGE_FILE_BYTES-byte safety limit."
                            )
                        }

                        val occurrences = findOccurrences(rangeFile, prefix, hashHex)
                        return PwnedPasswordExposureResult(
                            status = if (occurrences == null) {
                                PwnedPasswordExposureStatus.NOT_FOUND_IN_SNAPSHOT
                            } else {
                                PwnedPasswordExposureStatus.FOUND
                            },
                            occurrences = occurrences,
                            snapshotDate = snapshotDate
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

    private fun findOccurrences(rangeFile: Path, prefix: String, targetHash: String): Long? {
        var previousHash: String? = null
        var matchCount: Long? = null
        var lineCount = 0

        Files.newBufferedReader(rangeFile, StandardCharsets.UTF_8).use { reader ->
            while (true) {
                val line = reader.readLine() ?: break
                lineCount += 1
                if (lineCount > MAX_RANGE_LINES) {
                    throw IOException(
                        "Pwned Passwords range file exceeds the $MAX_RANGE_LINES-line safety limit."
                    )
                }
                if (line.length !in 42..60 || line[HASH_HEX_LENGTH] != ':') {
                    throw IOException("Pwned Passwords range file has an invalid record at line $lineCount.")
                }

                val hash = line.substring(0, HASH_HEX_LENGTH)
                if (hash.any { it !in '0'..'9' && it !in 'A'..'F' } || !hash.startsWith(prefix)) {
                    throw IOException("Pwned Passwords range file has an invalid hash at line $lineCount.")
                }
                previousHash?.let {
                    if (hash <= it) {
                        throw IOException("Pwned Passwords range file is not strictly sorted at line $lineCount.")
                    }
                }

                val countText = line.substring(HASH_HEX_LENGTH + 1)
                if (countText.length !in 1..19 || countText.any { it !in '0'..'9' }) {
                    throw IOException("Pwned Passwords range file has an invalid count at line $lineCount.")
                }
                val count = countText.toLongOrNull()
                    ?: throw IOException("Pwned Passwords range count is out of range at line $lineCount.")
                if (count <= 0 || count.toString() != countText) {
                    throw IOException("Pwned Passwords range count is not canonical at line $lineCount.")
                }

                if (hash == targetHash) matchCount = count
                previousHash = hash
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
