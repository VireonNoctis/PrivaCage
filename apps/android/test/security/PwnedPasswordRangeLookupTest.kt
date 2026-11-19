package org.privacage.security

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class PwnedPasswordRangeLookupTest {
    @TempDir
    lateinit var temporaryDirectory: Path

    private val snapshotDate = LocalDate.parse("2026-11-12")
    private val today = LocalDate.parse("2026-11-14")
    private val passwordHash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    private val prefix = "5BAA6"
    private val passwordSuffix = passwordHash.substring(prefix.length)

    @Test
    fun findsPasswordAndReturnsThePublishedOccurrenceCount() {
        writeRange("$passwordSuffix:3\n")
        val password = "password".toCharArray()
        val result = PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)

        assertEquals(PwnedPasswordExposureStatus.FOUND, result.status)
        assertEquals<ULong?>(3uL, result.occurrences)
        assertEquals(snapshotDate, result.snapshotDate)
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun validRangeWithoutPasswordReturnsOnlySnapshotScopedNoMatch() {
        val otherSuffix = "0".repeat(35)
        writeRange("$otherSuffix:1\n")
        val password = "password".toCharArray()
        val result = PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)

        assertEquals(PwnedPasswordExposureStatus.NOT_FOUND_IN_SNAPSHOT, result.status)
        assertNull(result.occurrences)
        assertEquals(snapshotDate, result.snapshotDate)
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun missingPrefixRangeIsAnErrorRatherThanANoMatch() {
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun emptyRangeIsUnavailableRatherThanANoMatch() {
        Files.write(temporaryDirectory.resolve("$prefix.txt"), ByteArray(0))
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsFullHashRecordsBecauseDirectoryFilesContainSuffixesOnly() {
        writeRange("$passwordHash:1\n")
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsSuffixesThatAreNotExactly35HexCharacters() {
        writeRange("0".repeat(34) + ":1\n")
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsLowercaseSuffixes() {
        writeRange(passwordSuffix.lowercase() + ":1\n")
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsUnsortedOrDuplicateRangeRecords() {
        val high = "F".repeat(35)
        val low = "0".repeat(35)
        writeRange("$high:1\n$low:1\n")
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsNonCanonicalOccurrenceCounts() {
        writeRange("$passwordSuffix:01\n")
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsOversizedRangeFilesBeforeParsing() {
        Files.write(
            temporaryDirectory.resolve("$prefix.txt"),
            ByteArray(PwnedPasswordRangeLookup.MAX_RANGE_FILE_BYTES + 1)
        )
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun acceptsCrlfAndAFinalRecordWithoutANewline() {
        val earlierSuffix = "0".repeat(35)
        writeRange("$earlierSuffix:1\r\n$passwordSuffix:3")
        val password = "password".toCharArray()

        val result = PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)

        assertEquals(PwnedPasswordExposureStatus.FOUND, result.status)
        assertEquals<ULong?>(3uL, result.occurrences)
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsARecordLongerThanTheFormatBound() {
        writeRange("0".repeat(56) + ":1\n")
        val password = "password".toCharArray()

        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun refusesSymbolicLinkRangeFiles() {
        val target = temporaryDirectory.resolve("range-target.txt")
        Files.write(target, "$passwordHash:3\n".toByteArray(StandardCharsets.US_ASCII))
        Files.createSymbolicLink(temporaryDirectory.resolve("$prefix.txt"), target.fileName)
        val password = "password".toCharArray()

        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsInvalidUnicodeAndClearsTheInput() {
        val password = charArrayOf('\uD800')
        assertFailsWith<IllegalArgumentException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsFutureSnapshotDatesAndClearsTheInput() {
        val password = "password".toCharArray()
        assertFailsWith<IllegalArgumentException> {
            PwnedPasswordRangeLookup.checkAndClear(
                password,
                temporaryDirectory,
                LocalDate.parse("2026-11-15"),
                today
            )
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun acceptsMaximumUnsigned64OccurrenceCountFromSharedGoVector() {
        writeRange(readSharedRangeVector("uint64-max.txt") + "\n")
        val password = "password".toCharArray()

        val result = PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)

        assertEquals(PwnedPasswordExposureStatus.FOUND, result.status)
        assertEquals<ULong?>(ULong.MAX_VALUE, result.occurrences)
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsUnsigned64OverflowFromSharedGoVector() {
        writeRange(readSharedRangeVector("uint64-overflow.txt") + "\n")
        val password = "password".toCharArray()

        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    private fun readSharedRangeVector(name: String): String {
        val stream = javaClass.getResourceAsStream("/pwned-password-ranges/$name")
            ?: error("Missing shared Pwned Passwords test vector: $name")
        return stream.bufferedReader(StandardCharsets.US_ASCII).use { it.readText().trimEnd('\r', '\n') }
    }

    private fun writeRange(content: String) {
        Files.write(temporaryDirectory.resolve("$prefix.txt"), content.toByteArray(StandardCharsets.US_ASCII))
    }
}
