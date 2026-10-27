package org.privacage.android

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkTrackerIndicatorScannerTest {
    private val evidence = listOf(
        TrackerEvidence(
            url = "https://docs.example.org/analytics",
            description = "Documents the analytics SDK integration."
        )
    )

    @Test
    fun findsDomainAndSdkIndicatorsWithEvidenceAndLifecycleStatus() {
        val apk = zippedDex(
            "classes.dex" to "x api.metrics.example.org x Lcom/example/analytics/Client; x"
        )
        try {
            val records = listOf(
                TrackerSignature(
                    id = "analytics-sdk",
                    name = "Example Analytics",
                    category = "analytics",
                    domains = emptyList(),
                    sdkPatterns = listOf("com.example.analytics.Client"),
                    confidence = "medium",
                    status = "active",
                    lastVerified = "2026-10-25",
                    evidence = evidence
                ),
                TrackerSignature(
                    id = "metrics-domain",
                    name = "Metrics endpoint",
                    category = "analytics",
                    domains = listOf("api.metrics.example.org"),
                    sdkPatterns = emptyList(),
                    confidence = "high",
                    status = "review",
                    lastVerified = "2026-10-25",
                    evidence = evidence
                )
            )

            val report = ApkTrackerIndicatorScanner().scan(apk, records)

            assertEquals(2, report.indicatorsConsidered)
            assertEquals(1, report.dexFilesScanned)
            assertTrue(report.dexBytesScanned > 0)
            assertEquals(setOf("analytics-sdk", "metrics-domain"), report.findings.map { it.recordId }.toSet())
            val sdk = report.findings.single { it.recordId == "analytics-sdk" }
            assertEquals("active", sdk.status)
            assertEquals("SDK pattern", sdk.indicatorType)
            assertEquals(listOf("classes.dex"), sdk.dexEntries)
            assertEquals(listOf("https://docs.example.org/analytics"), sdk.evidenceUrls)
            val domain = report.findings.single { it.recordId == "metrics-domain" }
            assertEquals("domain", domain.indicatorType)
            assertEquals("review", domain.status)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun findsLiteralWhenItCrossesTheInternalReadBufferBoundary() {
        val marker = "com.example.analytics.Client"
        val padding = "x".repeat(64 * 1024 - marker.length / 2)
        val apk = zippedDex("classes.dex" to (padding + marker + "x"))
        try {
            val record = TrackerSignature(
                id = "analytics-sdk",
                name = "Example Analytics",
                category = "analytics",
                domains = emptyList(),
                sdkPatterns = listOf(marker),
                confidence = "medium",
                status = "active",
                lastVerified = "2026-10-25",
                evidence = evidence
            )

            val report = ApkTrackerIndicatorScanner().scan(apk, listOf(record))

            assertEquals(1, report.findings.size)
            assertEquals("analytics-sdk", report.findings.single().recordId)
            assertTrue(report.dexBytesScanned >= 64 * 1024)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun reportsWhenArchiveHasNoDexEntries() {
        val apk = zippedDex("META-INF/MANIFEST.MF" to "not bytecode")
        try {
            val report = ApkTrackerIndicatorScanner().scan(
                apk,
                listOf(
                    TrackerSignature(
                        id = "sample-domain",
                        name = "Sample",
                        category = "analytics",
                        domains = listOf("tracker.example.org"),
                        sdkPatterns = emptyList(),
                        confidence = "low",
                        status = "review",
                        lastVerified = "2026-10-25",
                        evidence = evidence
                    )
                )
            )

            assertEquals(0, report.dexFilesScanned)
            assertEquals(0L, report.dexBytesScanned)
            assertTrue(report.findings.isEmpty())
            assertTrue(report.warnings.any { it.contains("No DEX entries") })
        } finally {
            apk.delete()
        }
    }

    @Test
    fun rejectsMalformedZipRatherThanReturningAnEmptyCleanReport() {
        val apk = Files.createTempFile("privacage-malformed-apk-", ".apk").toFile()
        try {
            apk.writeText("this is not a ZIP archive")
            val record = TrackerSignature(
                id = "sample-domain",
                name = "Sample",
                category = "analytics",
                domains = listOf("tracker.example.org"),
                sdkPatterns = emptyList(),
                confidence = "low",
                status = "review",
                lastVerified = "2026-10-25",
                evidence = evidence
            )
            val error = runCatching { ApkTrackerIndicatorScanner().scan(apk, listOf(record)) }.exceptionOrNull()
            assertTrue("Malformed archive must surface an error", error is java.io.IOException)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun identicalApkAndCatalogProduceByteStableFindings() {
        val apk = zippedDex(
            "classes.dex" to "x com.example.analytics.Client x api.metrics.example.org x"
        )
        try {
            val records = listOf(
                TrackerSignature(
                    id = "analytics-sdk",
                    name = "Example Analytics",
                    category = "analytics",
                    domains = emptyList(),
                    sdkPatterns = listOf("com.example.analytics.Client"),
                    confidence = "medium",
                    status = "active",
                    lastVerified = "2026-10-25",
                    evidence = evidence
                ),
                TrackerSignature(
                    id = "metrics-domain",
                    name = "Metrics endpoint",
                    category = "analytics",
                    domains = listOf("api.metrics.example.org"),
                    sdkPatterns = emptyList(),
                    confidence = "high",
                    status = "review",
                    lastVerified = "2026-10-25",
                    evidence = evidence
                )
            )
            val scanner = ApkTrackerIndicatorScanner()

            val first = scanner.scan(apk, records)
            val second = scanner.scan(apk, records)

            assertEquals(first, second)
            assertTrue("Static matches must not be described as runtime observations.", first.warnings.none {
                it.contains("transmitted", ignoreCase = true) || it.contains("executed", ignoreCase = true)
            })
        } finally {
            apk.delete()
        }
    }

    private fun zippedDex(vararg entries: Pair<String, String>): File {
        val apk = Files.createTempFile("privacage-apk-scan-", ".apk").toFile()
        ZipOutputStream(FileOutputStream(apk)).use { zip ->
            entries.forEach { (name, value) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(value.toByteArray(Charsets.US_ASCII))
                zip.closeEntry()
            }
        }
        return apk
    }
}
