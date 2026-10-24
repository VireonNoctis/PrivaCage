package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Test
import org.privacage.audit.PermissionRiskClassifier

class ApkPrivacyDiffTest {
    @Test
    fun reportsPermissionComponentAndEmbeddedIndicatorChanges() {
        val baseline = report(
            versionName = "1.0",
            versionCode = 1,
            permissions = listOf(INTERNET, CAMERA),
            components = listOf(
                ExportedApkComponent("Service", "com.example.SyncService", true, null),
                ExportedApkComponent("Activity", "com.example.LegacyActivity", true, null)
            ),
            findings = listOf(
                indicator("shared-tracker", "shared.example", status = "review"),
                indicator("removed-tracker", "old.example")
            )
        )
        val candidate = report(
            versionName = "2.0",
            versionCode = 2,
            permissions = listOf(INTERNET, FINE_LOCATION),
            components = listOf(
                ExportedApkComponent("Service", "com.example.SyncService", true, "android.permission.BIND_JOB_SERVICE"),
                ExportedApkComponent("Receiver", "com.example.UpdateReceiver", true, null)
            ),
            findings = listOf(
                indicator("shared-tracker", "shared.example", status = "active", dexEntry = "classes2.dex"),
                indicator("new-tracker", "new.example")
            )
        )

        val diff = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(listOf(FINE_LOCATION), diff.addedPermissions.map { it.permissionName })
        assertEquals(listOf(CAMERA), diff.removedPermissions.map { it.permissionName })
        assertEquals(listOf("com.example.UpdateReceiver"), diff.addedExportedComponents.map { it.className })
        assertEquals(listOf("com.example.LegacyActivity"), diff.removedExportedComponents.map { it.className })
        assertEquals(1, diff.changedExportedComponents.size)
        assertEquals("com.example.SyncService", diff.changedExportedComponents.single().before.className)
        assertEquals("android.permission.BIND_JOB_SERVICE", diff.changedExportedComponents.single().after.requiredPermission)
        assertEquals(listOf("new.example"), diff.addedTrackerIndicators.map { it.indicator })
        assertEquals(listOf("old.example"), diff.removedTrackerIndicators.map { it.indicator })
        assertEquals(1, diff.changedTrackerIndicators.size)
        assertEquals("review", diff.changedTrackerIndicators.single().before.status)
        assertEquals("active", diff.changedTrackerIndicators.single().after.status)
        assertEquals(CATALOG_SHA256, diff.trackerCatalogSha256)
    }

    @Test(expected = IllegalArgumentException::class)
    fun refusesToCompareDifferentPackages() {
        ApkPrivacyDiff.compare(
            report(packageName = "com.example.first"),
            report(packageName = "com.example.second"),
            CATALOG_SHA256
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun refusesAnInvalidCatalogFingerprint() {
        ApkPrivacyDiff.compare(report(), report(versionCode = 2), "unknown")
    }

    private fun report(
        packageName: String = "com.example.app",
        versionName: String = "1.0",
        versionCode: Long = 1L,
        permissions: List<String> = emptyList(),
        components: List<ExportedApkComponent> = emptyList(),
        findings: List<ApkTrackerIndicatorFinding> = emptyList()
    ) = ApkManifestAuditReport(
        packageName = packageName,
        versionName = versionName,
        versionCode = versionCode,
        targetSdkVersion = 35,
        fileSizeBytes = 10_000L,
        sha256 = "b".repeat(64),
        signingCertificateSha256 = listOf("c".repeat(64)),
        signatureVerification = ApkSignatureVerification(ApkSignatureStatus.VERIFIED, emptyList(), emptyList()),
        permissions = permissions.map { ApkPermissionFinding(it, PermissionRiskClassifier.classify(it)) },
        exportedComponents = components,
        trackerScan = ApkTrackerScanReport(
            indicatorsConsidered = 4,
            dexFilesScanned = 1,
            dexBytesScanned = 128L,
            findings = findings,
            warnings = emptyList()
        )
    )

    private fun indicator(
        recordId: String,
        value: String,
        status: String = "active",
        dexEntry: String = "classes.dex"
    ) = ApkTrackerIndicatorFinding(
        recordId = recordId,
        recordName = recordId,
        category = "analytics",
        status = status,
        confidence = "medium",
        indicatorType = "domain",
        indicator = value,
        dexEntries = listOf(dexEntry),
        evidenceUrls = listOf("https://example.org/evidence")
    )

    private companion object {
        const val INTERNET = "android.permission.INTERNET"
        const val CAMERA = "android.permission.CAMERA"
        const val FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION"
        val CATALOG_SHA256 = "a".repeat(64)
    }
}
