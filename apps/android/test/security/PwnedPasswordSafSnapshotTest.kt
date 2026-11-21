package org.privacage.security

import java.io.ByteArrayInputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class PwnedPasswordSafSnapshotTest {
    @TempDir
    lateinit var cacheDirectory: Path

    private val today = LocalDate.parse("2026-11-21")
    private val snapshotDate = LocalDate.parse("2026-11-20")
    private val matchingPassword = "pcage-saf-424592"
    private val matchingSuffix = "6E9E13AE40B6176984B3B82CD0145E03333"

    private data class Document(val name: String, val bytes: ByteArray)

    private class FakeDocuments(
        private val values: Map<String, Document>,
        private val failOnOpen: String? = null
    ) : PwnedPasswordDocumentAccess {
        override fun displayName(uri: String): String? = values[uri]?.name

        override fun open(uri: String): ByteArrayInputStream? {
            if (uri == failOnOpen) throw IOException("provider read failed")
            return values[uri]?.bytes?.copyOf()?.let(::ByteArrayInputStream)
        }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02X".format(it.toInt() and 0xff) }

    private fun dataset(
        selectedPrefix: String = "00000",
        rangeBytes: ByteArray = "$matchingSuffix:7\n".toByteArray(StandardCharsets.US_ASCII),
        rangeName: String = "$selectedPrefix.txt",
        expectedDigestOverride: String? = null,
        failOnOpen: String? = null
    ): Triple<FakeDocuments, String, String> {
        val ranges = (0 until 4).associate { index ->
            index.toString(16).uppercase().padStart(5, '0') to ByteArray(0)
        }.toMutableMap()
        ranges["00000"] = "$matchingSuffix:7\n".toByteArray(StandardCharsets.US_ASCII)
        ranges[selectedPrefix] = rangeBytes

        val entries = StringBuilder()
        var totalBytes = 0L
        var totalRecords = 0L
        for (index in 0 until 4) {
            val prefix = index.toString(16).uppercase().padStart(5, '0')
            val bytes = ranges.getValue(prefix)
            val records = if (bytes.isEmpty()) 0L else 1L
            totalBytes += bytes.size.toLong()
            totalRecords += records
            entries.append("{\"prefix\":\"").append(prefix)
                .append("\",\"size\":").append(bytes.size)
                .append(",\"records\":").append(records)
                .append(",\"sha256\":\"").append(sha256(bytes)).append("\"}\n")
        }
        val header = buildString {
            append("{\"type\":\"pcage-pwned-password-ranges\",\"version\":1,")
            append("\"source\":\"HIBP-Pwned-Passwords\",\"hash\":\"SHA-1\",")
            append("\"snapshot_date\":\"").append(snapshotDate).append("\",")
            append("\"generated_at\":\"2026-11-20T10:00:00Z\",")
            append("\"range_count\":4,\"total_bytes\":").append(totalBytes)
            append(",\"total_records\":").append(totalRecords).append("}\n")
        }
        val manifest = (header + entries).toByteArray(StandardCharsets.US_ASCII)
        val digest = expectedDigestOverride ?: sha256(manifest)
        val documents = FakeDocuments(
            mapOf(
                "manifest" to Document("manifest.jsonl", manifest),
                "range" to Document(rangeName, rangeBytes)
            ),
            failOnOpen
        )
        return Triple(documents, digest, selectedPrefix)
    }

    private fun prepare(
        documents: PwnedPasswordDocumentAccess,
        digest: String,
        expectedRangeCount: Int = 4
    ) = PwnedPasswordSafSnapshot.prepare(
        manifestUri = "manifest",
        expectedManifestSha256 = digest,
        rangeUri = "range",
        documents = documents,
        cacheDirectory = cacheDirectory,
        expectedRangeCount = expectedRangeCount
    )

    @Test
    fun snapshotsOnlyTheSelectedManifestAndRangeThenVerifiesTheMatch() {
        val (documents, digest) = dataset()
        val snapshot = prepare(documents, digest)
        val directory = snapshot.snapshotDirectoryForTest

        assertTrue(Files.exists(directory.resolve("manifest.jsonl")))
        assertTrue(Files.exists(directory.resolve("00000.txt")))

        val password = matchingPassword.toCharArray()
        val result = snapshot.checkAndClear(password, today)

        assertEquals(PwnedPasswordExposureStatus.FOUND, result.status)
        assertEquals<ULong?>(7uL, result.occurrences)
        assertEquals(snapshotDate, result.snapshotDate)
        assertTrue(password.all { it == '\u0000' })

        snapshot.close()
        assertFalse(Files.exists(directory))
        assertEquals(0L, Files.list(cacheDirectory).use { it.count() })
    }

    @Test
    fun verifiedEmptyRangeReturnsOnlySnapshotScopedNoMatch() {
        val (documents, digest) = dataset(
            selectedPrefix = "00001",
            rangeBytes = ByteArray(0)
        )
        val snapshot = prepare(documents, digest)
        val password = "pcage-empty-114265".toCharArray()

        val result = snapshot.checkAndClear(password, today)

        assertEquals(PwnedPasswordExposureStatus.NOT_FOUND_IN_SNAPSHOT, result.status)
        assertEquals(snapshotDate, result.snapshotDate)
        assertTrue(password.all { it == '\u0000' })
        snapshot.close()
    }

    @Test
    fun wrongSelectedPrefixFailsWithTheRequiredPrefixAndClearsPassword() {
        val (documents, digest) = dataset(
            selectedPrefix = "00001",
            rangeBytes = ByteArray(0)
        )
        val snapshot = prepare(documents, digest)
        val password = matchingPassword.toCharArray()

        val failure = assertFailsWith<IOException> {
            snapshot.checkAndClear(password, today)
        }

        assertTrue(failure.message.orEmpty().contains("required prefix 00000"))
        assertTrue(password.all { it == '\u0000' })
        snapshot.close()
    }

    @Test
    fun digestMismatchCannotProduceAMatchOrNoMatch() {
        val (documents, _) = dataset(expectedDigestOverride = "0".repeat(64))
        val snapshot = prepare(documents, "0".repeat(64))
        val password = matchingPassword.toCharArray()

        assertFailsWith<IOException> { snapshot.checkAndClear(password, today) }
        assertTrue(password.all { it == '\u0000' })
        snapshot.close()
    }

    @Test
    fun oversizedRangeIsRejectedAndPartialSnapshotIsRemoved() {
        val oversized = ByteArray(PwnedPasswordRangeLookup.MAX_RANGE_FILE_BYTES + 1)
        val (documents, digest) = dataset(rangeBytes = oversized)

        assertFailsWith<IOException> { prepare(documents, digest) }
        assertEquals(0L, Files.list(cacheDirectory).use { it.count() })
    }

    @Test
    fun invalidRangeNameIsRejectedBeforeCreatingCacheSnapshot() {
        val (documents, digest) = dataset(rangeName = "0000a.txt")

        assertFailsWith<IOException> { prepare(documents, digest) }
        assertEquals(0L, Files.list(cacheDirectory).use { it.count() })
    }

    @Test
    fun providerFailureAfterManifestCopyRemovesPartialSnapshot() {
        val (documents, digest) = dataset(failOnOpen = "range")

        assertFailsWith<IOException> { prepare(documents, digest) }
        assertEquals(0L, Files.list(cacheDirectory).use { it.count() })
    }

    @Test
    fun closedSnapshotRejectsLookupAndStillClearsPassword() {
        val (documents, digest) = dataset()
        val snapshot = prepare(documents, digest)
        snapshot.close()
        snapshot.close()
        val password = matchingPassword.toCharArray()

        assertFailsWith<IOException> { snapshot.checkAndClear(password, today) }
        assertTrue(password.all { it == '\u0000' })
    }
}
