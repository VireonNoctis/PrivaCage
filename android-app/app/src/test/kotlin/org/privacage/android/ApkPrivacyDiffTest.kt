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

    @Test
    fun recognizesPlatformProvidedForwardCertificateRotation() {
        val baseline = report(
            versionCode = 10,
            signingHistory = listOf(CERT_A)
        )
        val candidate = report(
            versionCode = 11,
            signingHistory = listOf(CERT_A, CERT_B)
        )

        val diff = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(ApkSigningCertificateContinuity.AUTHORIZED_ROTATION, diff.signingCertificateContinuity)
    }

    @Test
    fun identifiesEarlierSignerLineageAsPossibleDowngrade() {
        val baseline = report(
            versionCode = 11,
            signingHistory = listOf(CERT_A, CERT_B)
        )
        val candidate = report(
            versionCode = 10,
            signingHistory = listOf(CERT_A)
        )

        val diff = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(ApkSigningCertificateContinuity.POSSIBLE_DOWNGRADE, diff.signingCertificateContinuity)
    }

    @Test
    fun identifiesLineageRegressionWithoutLowerVersionCode() {
        val baseline = report(
            versionCode = 10,
            signingHistory = listOf(CERT_A, CERT_B)
        )
        val candidate = report(
            versionCode = 11,
            signingHistory = listOf(CERT_A)
        )

        val diff = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(ApkSigningCertificateContinuity.LINEAGE_REGRESSION, diff.signingCertificateContinuity)
    }

    @Test
    fun unrelatedSigningHistoriesAreNotReportedAsAuthorizedRotation() {
        val baseline = report(versionCode = 10, signingHistory = listOf(CERT_A))
        val candidate = report(versionCode = 11, signingHistory = listOf(CERT_C))

        val diff = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(ApkSigningCertificateContinuity.SIGNER_MISMATCH, diff.signingCertificateContinuity)
    }

    @Test
    fun missingPlatformHistoryRemainsUnknown() {
        val baseline = report(
            versionCode = 10,
            signingHistory = listOf(CERT_A),
            historyStatus = ApkSigningCertificateHistoryStatus.PLATFORM_UNSUPPORTED
        )
        val candidate = report(
            versionCode = 11,
            signingHistory = listOf(CERT_A, CERT_B)
        )

        val diff = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(ApkSigningCertificateContinuity.UNKNOWN, diff.signingCertificateContinuity)
    }

    @Test
    fun multipleSignerIdentityIsComparedAsAnUnorderedSet() {
        val baseline = report(
            versionCode = 10,
            signers = listOf(CERT_A, CERT_B),
            signingHistory = emptyList(),
            historyStatus = ApkSigningCertificateHistoryStatus.MULTIPLE_SIGNERS
        )
        val candidate = report(
            versionCode = 11,
            signers = listOf(CERT_B, CERT_A),
            signingHistory = emptyList(),
            historyStatus = ApkSigningCertificateHistoryStatus.MULTIPLE_SIGNERS
        )

        val diff = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(ApkSigningCertificateContinuity.UNCHANGED, diff.signingCertificateContinuity)
    }

    @Test
    fun multipleSignerSetChangesAreNotTreatedAsRotation() {
        val baseline = report(
            versionCode = 10,
            signers = listOf(CERT_A, CERT_B),
            signingHistory = emptyList(),
            historyStatus = ApkSigningCertificateHistoryStatus.MULTIPLE_SIGNERS
        )
        val candidate = report(
            versionCode = 11,
            signers = listOf(CERT_A, CERT_C),
            signingHistory = emptyList(),
            historyStatus = ApkSigningCertificateHistoryStatus.MULTIPLE_SIGNERS
        )

        val diff = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(ApkSigningCertificateContinuity.SIGNER_MISMATCH, diff.signingCertificateContinuity)
    }

    @Test
    fun changingBetweenSingleAndMultipleSignerModelsIsNotRotation() {
        val baseline = report(
            versionCode = 10,
            signingHistory = listOf(CERT_A)
        )
        val candidate = report(
            versionCode = 11,
            signers = listOf(CERT_A, CERT_B),
            signingHistory = emptyList(),
            historyStatus = ApkSigningCertificateHistoryStatus.MULTIPLE_SIGNERS
        )

        val diff = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(ApkSigningCertificateContinuity.SIGNER_MODEL_CHANGED, diff.signingCertificateContinuity)
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

    @Test
    fun identicalInputsAndCatalogFingerprintProduceIdenticalDiffs() {
        val baseline = report(
            versionName = "1.0",
            versionCode = 1,
            permissions = listOf(INTERNET, CAMERA),
            components = listOf(ExportedApkComponent("Service", "com.example.SyncService", true, null)),
            findings = listOf(indicator("analytics", "metrics.example"))
        )
        val candidate = report(
            versionName = "2.0",
            versionCode = 2,
            permissions = listOf(INTERNET, CAMERA, FINE_LOCATION),
            components = listOf(ExportedApkComponent("Service", "com.example.SyncService", true, null)),
            findings = listOf(indicator("analytics", "metrics.example"))
        )

        val first = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)
        val second = ApkPrivacyDiff.compare(baseline, candidate, CATALOG_SHA256)

        assertEquals(first, second)
        assertEquals(listOf(FINE_LOCATION), first.addedPermissions.map { it.permissionName })
    }

    private fun report(
        packageName: String = "com.example.app",
        versionName: String = "1.0",
        versionCode: Long = 1L,
        permissions: List<String> = emptyList(),
        components: List<ExportedApkComponent> = emptyList(),
        findings: List<ApkTrackerIndicatorFinding> = emptyList(),
        signers: List<String> = listOf(CERT_A),
        signingHistory: List<String> = signers,
        historyStatus: ApkSigningCertificateHistoryStatus = ApkSigningCertificateHistoryStatus.AVAILABLE
    ) = ApkManifestAuditReport(
        packageName = packageName,
        versionName = versionName,
        versionCode = versionCode,
        targetSdkVersion = 35,
        fileSizeBytes = 10_000L,
        sha256 = "b".repeat(64),
        signingCertificateSha256 = signers.sorted(),
        signatureVerification = ApkSignatureVerification(ApkSignatureStatus.VERIFIED, emptyList(), emptyList()),
        permissions = permissions.map { ApkPermissionFinding(it, PermissionRiskClassifier.classify(it)) },
        exportedComponents = components,
        trackerScan = ApkTrackerScanReport(
            status = ApkDexStringScanStatus.COMPLETE_STRING_SCAN,
            indicatorsConsidered = 4,
            dexFilesScanned = 1,
            dexBytesScanned = 128L,
            findings = findings,
            warnings = emptyList()
        ),
        signingCertificateHistorySha256 = signingHistory,
        signingCertificateHistoryStatus = historyStatus
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
        val CERT_A = "a".repeat(64)
        val CERT_B = "b".repeat(64)
        val CERT_C = "c".repeat(64)
        const val INTERNET = "android.permission.INTERNET"
        const val CAMERA = "android.permission.CAMERA"
        const val FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION"
        val CATALOG_SHA256 = "a".repeat(64)
    }
}
