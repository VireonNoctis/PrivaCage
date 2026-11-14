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

    @Test
    fun findsPasswordAndReturnsThePublishedOccurrenceCount() {
        writeRange("$passwordHash:3\n")
        val password = "password".toCharArray()
        val result = PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)

        assertEquals(PwnedPasswordExposureStatus.FOUND, result.status)
        assertEquals(3L, result.occurrences)
        assertEquals(snapshotDate, result.snapshotDate)
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun validRangeWithoutPasswordReturnsOnlySnapshotScopedNoMatch() {
        val otherHash = prefix + "0".repeat(35)
        writeRange("$otherHash:1\n")
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
        Files.writeString(temporaryDirectory.resolve("$prefix.txt"), "", StandardCharsets.US_ASCII)
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsAHashFromAnotherPrefix() {
        writeRange("5BAA7" + "0".repeat(35) + ":1\n")
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsUnsortedOrDuplicateRangeRecords() {
        val high = prefix + "F".repeat(35)
        val low = prefix + "0".repeat(35)
        writeRange("$high:1\n$low:1\n")
        val password = "password".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClear(password, temporaryDirectory, snapshotDate, today)
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun rejectsNonCanonicalOccurrenceCounts() {
        writeRange("$passwordHash:01\n")
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

    private fun writeRange(content: String) {
        Files.writeString(temporaryDirectory.resolve("$prefix.txt"), content, StandardCharsets.US_ASCII)
    }
}
