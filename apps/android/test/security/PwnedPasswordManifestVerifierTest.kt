package org.privacage.security

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class PwnedPasswordManifestVerifierTest {
    @TempDir
    lateinit var temporaryDirectory: Path

    private val fixtureRoot: Path
        get() {
            val repositoryRoot = System.getProperty("privacage.repo-root")
                ?: error("Missing privacage.repo-root test property")
            return Path.of(repositoryRoot)
                .resolve("shared/crypto/test-vectors/pwned-password-manifest/v1")
        }

    private fun copyFixtureRanges(): Path {
        val source = fixtureRoot.resolve("ranges")
        val target = temporaryDirectory.resolve("ranges")
        Files.createDirectories(target)
        for (index in 0 until 4) {
            val prefix = index.toString(16).uppercase().padStart(5, '0')
            Files.copy(source.resolve(prefix + ".txt"), target.resolve(prefix + ".txt"))
        }
        return target
    }

    private fun fixtureManifest(): Path = fixtureRoot.resolve("manifest.jsonl")

    private fun expectedDigest(): String = String(
        Files.readAllBytes(fixtureRoot.resolve("manifest.sha256")),
        StandardCharsets.US_ASCII
    ).trim()

    private fun sha256(path: Path): String =
        MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(path))
            .joinToString("") { "%02X".format(it.toInt() and 0xff) }

    private fun verify(path: Path, selectedPrefix: String = "00000") =
        PwnedPasswordManifestVerifier.verify(
            path,
            sha256(path),
            selectedPrefix,
            LocalDate.parse("2026-11-20"),
            expectedRangeCount = 4
        )

    @Test
    fun verifiesSharedGoManifestVectorAndSelectsTheRequestedPrefix() {
        val verified = PwnedPasswordManifestVerifier.verify(
            fixtureManifest(),
            expectedDigest(),
            "00000",
            LocalDate.parse("2026-11-20"),
            expectedRangeCount = 4
        )

        assertEquals(LocalDate.parse("2026-11-19"), verified.snapshotDate)
        assertEquals("00000", verified.selectedRange.prefix)
        assertEquals(118, verified.selectedRange.sizeBytes)
        assertEquals(3uL, verified.selectedRange.recordCount)
        assertEquals(
            "73419B636F39B3F6FE1BCD2393CE03B61959E7560288B43C12207E5A5BC7D768",
            verified.selectedRange.sha256
        )
    }

    @Test
    fun rejectsManifestDigestMismatch() {
        assertFailsWith<IOException> {
            PwnedPasswordManifestVerifier.verify(
                fixtureManifest(),
                "0".repeat(64),
                "00000",
                LocalDate.parse("2026-11-20"),
                expectedRangeCount = 4
            )
        }
    }

    @Test
    fun rejectsDuplicateAndUnknownJsonFieldsEvenWhenTheirDigestIsTrusted() {
        val original = String(Files.readAllBytes(fixtureManifest()), StandardCharsets.US_ASCII)
        val duplicate = original.replaceFirst(
            "\"version\":1",
            "\"version\":1,\"version\":1"
        )
        val duplicatePath = temporaryDirectory.resolve("duplicate.jsonl")
        Files.write(duplicatePath, duplicate.toByteArray(StandardCharsets.US_ASCII))
        assertFailsWith<IOException> { verify(duplicatePath) }

        val unknown = original.replaceFirst(
            "\"version\":1",
            "\"version\":1,\"unexpected\":true"
        )
        val unknownPath = temporaryDirectory.resolve("unknown.jsonl")
        Files.write(unknownPath, unknown.toByteArray(StandardCharsets.US_ASCII))
        assertFailsWith<IOException> { verify(unknownPath) }
    }

    @Test
    fun rejectsMissingEntriesTrailingDataAndIncorrectTotals() {
        val original = String(Files.readAllBytes(fixtureManifest()), StandardCharsets.US_ASCII)
        val lastEntry = original.lastIndexOf("{\"prefix\":\"00003\"")
        assertTrue(lastEntry > 0)
        val missingPath = temporaryDirectory.resolve("missing.jsonl")
        Files.write(missingPath, original.substring(0, lastEntry).toByteArray(StandardCharsets.US_ASCII))
        assertFailsWith<IOException> { verify(missingPath) }

        val trailingPath = temporaryDirectory.resolve("trailing.jsonl")
        Files.write(trailingPath, (original + "{}\n").toByteArray(StandardCharsets.US_ASCII))
        assertFailsWith<IOException> { verify(trailingPath) }

        val totals = original.replaceFirst("\"total_records\":5", "\"total_records\":6")
        val totalsPath = temporaryDirectory.resolve("totals.jsonl")
        Files.write(totalsPath, totals.toByteArray(StandardCharsets.US_ASCII))
        assertFailsWith<IOException> { verify(totalsPath) }
    }

    @Test
    fun acceptsCrlfJsonlButRejectsAnUnterminatedFinalRecord() {
        val original = String(Files.readAllBytes(fixtureManifest()), StandardCharsets.US_ASCII)
        val crlfPath = temporaryDirectory.resolve("crlf.jsonl")
        Files.write(crlfPath, original.replace("\n", "\r\n").toByteArray(StandardCharsets.US_ASCII))
        assertEquals("00000", verify(crlfPath).selectedRange.prefix)

        val unterminatedPath = temporaryDirectory.resolve("unterminated.jsonl")
        Files.write(unterminatedPath, original.dropLast(1).toByteArray(StandardCharsets.US_ASCII))
        assertFailsWith<IOException> { verify(unterminatedPath) }
    }

    @Test
    fun rejectsOverlongManifestLinesBeforeJsonParsing() {
        val path = temporaryDirectory.resolve("overlong.jsonl")
        Files.write(path, ("x".repeat(4 * 1024 + 1) + "\n").toByteArray(StandardCharsets.US_ASCII))
        assertFailsWith<IOException> { verify(path) }
    }

    @Test
    fun rejectsFutureSnapshotAndIncompletePrefixCoverage() {
        assertFailsWith<IOException> {
            PwnedPasswordManifestVerifier.verify(
                fixtureManifest(), expectedDigest(), "00000",
                LocalDate.parse("2026-11-18"), expectedRangeCount = 4
            )
        }
        assertFailsWith<IOException> {
            PwnedPasswordManifestVerifier.verify(
                fixtureManifest(), expectedDigest(), "00003",
                LocalDate.parse("2026-11-20"), expectedRangeCount = 3
            )
        }
    }

    @Test
    fun rejectsSymbolicLinkManifest() {
        val link = temporaryDirectory.resolve("manifest-link.jsonl")
        try {
            Files.createSymbolicLink(link, fixtureManifest())
        } catch (exception: UnsupportedOperationException) {
            return
        } catch (exception: IOException) {
            return
        } catch (exception: SecurityException) {
            return
        }
        assertFailsWith<IOException> { verify(link) }
    }

    @Test
    fun manifestBoundLookupMatchesOnlyAfterSelectedRangeDigestAndRecordCountVerify() {
        val ranges = copyFixtureRanges()
        val password = "pcage-test-1159308".toCharArray()
        val result = PwnedPasswordRangeLookup.checkAndClearWithManifest(
            password,
            ranges,
            fixtureManifest(),
            expectedDigest(),
            today = LocalDate.parse("2026-11-20"),
            expectedRangeCount = 4
        )

        assertEquals(PwnedPasswordExposureStatus.FOUND, result.status)
        assertEquals<ULong?>(42uL, result.occurrences)
        assertEquals(LocalDate.parse("2026-11-19"), result.snapshotDate)
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun verifiedEmptyRangeCanReturnSnapshotScopedNoMatch() {
        val ranges = copyFixtureRanges()
        val password = "pcage-test-982295".toCharArray()
        val result = PwnedPasswordRangeLookup.checkAndClearWithManifest(
            password,
            ranges,
            fixtureManifest(),
            expectedDigest(),
            today = LocalDate.parse("2026-11-20"),
            expectedRangeCount = 4
        )

        assertEquals(PwnedPasswordExposureStatus.NOT_FOUND_IN_SNAPSHOT, result.status)
        assertNull(result.occurrences)
        assertEquals(LocalDate.parse("2026-11-19"), result.snapshotDate)
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun changedSelectedRangeCannotProduceAMatchOrNoMatch() {
        val ranges = copyFixtureRanges()
        Files.write(
            ranges.resolve("00000.txt"),
            "00000000000000000000000000000000000:1\n".toByteArray(StandardCharsets.US_ASCII)
        )
        val password = "pcage-test-1159308".toCharArray()

        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClearWithManifest(
                password,
                ranges,
                fixtureManifest(),
                expectedDigest(),
                today = LocalDate.parse("2026-11-20"),
                expectedRangeCount = 4
            )
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun selectedRangeRecordCountMustMatchEvenWhenManifestDigestMatches() {
        val original = String(Files.readAllBytes(fixtureManifest()), StandardCharsets.US_ASCII)
        val changed = original
            .replaceFirst("\"records\":3", "\"records\":2")
            .replaceFirst("\"total_records\":5", "\"total_records\":4")
        val manifest = temporaryDirectory.resolve("wrong-record-count.jsonl")
        Files.write(manifest, changed.toByteArray(StandardCharsets.US_ASCII))
        val ranges = copyFixtureRanges()
        val password = "pcage-test-1159308".toCharArray()

        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClearWithManifest(
                password,
                ranges,
                manifest,
                sha256(manifest),
                today = LocalDate.parse("2026-11-20"),
                expectedRangeCount = 4
            )
        }
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun missingManifestOrSelectedRangeIsUnavailable() {
        val ranges = copyFixtureRanges()
        val missingManifestPassword = "pcage-test-1159308".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClearWithManifest(
                missingManifestPassword,
                ranges,
                temporaryDirectory.resolve("missing.jsonl"),
                expectedDigest(),
                today = LocalDate.parse("2026-11-20"),
                expectedRangeCount = 4
            )
        }
        assertTrue(missingManifestPassword.all { it == '\u0000' })

        Files.delete(ranges.resolve("00000.txt"))
        val missingRangePassword = "pcage-test-1159308".toCharArray()
        assertFailsWith<IOException> {
            PwnedPasswordRangeLookup.checkAndClearWithManifest(
                missingRangePassword,
                ranges,
                fixtureManifest(),
                expectedDigest(),
                today = LocalDate.parse("2026-11-20"),
                expectedRangeCount = 4
            )
        }
        assertTrue(missingRangePassword.all { it == '\u0000' })
    }
}
