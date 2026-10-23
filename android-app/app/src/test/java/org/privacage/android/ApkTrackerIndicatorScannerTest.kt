package org.privacage.android

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkTrackerIndicatorScannerTest {

    @Test
    fun findsCatalogDomainInDexAcrossReadBufferBoundary() {
        val temp = File.createTempFile("privacage-scanner-test-", ".apk")
        try {
            val dexBytes = ByteArray(65_530) { 'x'.code.toByte() } +
                "https://WWW.CLARITY.MS/collect".toByteArray(Charsets.US_ASCII)
            writeArchive(temp, "classes.dex" to dexBytes)

            val report = ApkTrackerIndicatorScanner().scan(temp, listOf(signature()))

            assertEquals(1, report.dexFilesScanned)
            assertTrue(report.dexBytesScanned > 0)
            assertEquals(1, report.findings.size)
            assertEquals("microsoft-clarity-collection", report.findings.single().recordId)
            assertEquals("www.clarity.ms", report.findings.single().indicator)
            assertEquals(listOf("classes.dex"), report.findings.single().dexEntries)
        } finally {
            temp.delete()
        }
    }

    @Test
    fun scansLiteralSdkPackageAndSlashForm() {
        val temp = File.createTempFile("privacage-scanner-test-", ".apk")
        try {
            writeArchive(temp, "classes2.dex" to "com.vendor.analytics.Client".toByteArray())
            val report = ApkTrackerIndicatorScanner().scan(
                temp,
                listOf(signature(domains = emptyList(), sdkPatterns = listOf("com.vendor.analytics.Client")))
            )

            assertEquals(1, report.findings.size)
            assertEquals("SDK pattern", report.findings.single().indicatorType)
        } finally {
            temp.delete()
        }
    }

    @Test
    fun reportsReviewOnlyMatchesWithoutPromotingThemToActive() {
        val temp = File.createTempFile("privacage-scanner-test-", ".apk")
        try {
            writeArchive(temp, "classes.dex" to "https://doubleclick.net/activity".toByteArray())
            val report = ApkTrackerIndicatorScanner().scan(
                temp,
                listOf(signature(domains = listOf("doubleclick.net"), status = "review"))
            )

            assertEquals("review", report.findings.single().status)
        } finally {
            temp.delete()
        }
    }

    @Test
    fun warnsWhenArchiveContainsNoDexFiles() {
        val temp = File.createTempFile("privacage-scanner-test-", ".apk")
        try {
            writeArchive(temp, "assets/readme.txt" to "clarity.ms".toByteArray())
            val report = ApkTrackerIndicatorScanner().scan(temp, listOf(signature()))

            assertTrue(report.findings.isEmpty())
            assertTrue(report.warnings.any { it.contains("No DEX entries") })
        } finally {
            temp.delete()
        }
    }

    private fun signature(
        domains: List<String> = listOf("www.clarity.ms"),
        sdkPatterns: List<String> = emptyList(),
        status: String = "active"
    ) = TrackerSignature(
        id = if (status == "review") "review-indicator" else "microsoft-clarity-collection",
        name = "Test tracker indicator",
        category = "analytics",
        domains = domains,
        sdkPatterns = sdkPatterns,
        confidence = "high",
        status = status,
        lastVerified = "2026-10-23",
        evidence = listOf(TrackerEvidence("https://example.org/docs", "Test fixture provenance"))
    )

    private fun writeArchive(file: File, vararg entries: Pair<String, ByteArray>) {
        ZipOutputStream(file.outputStream()).use { zip ->
            for ((name, content) in entries) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(content)
                zip.closeEntry()
            }
        }
    }
}
