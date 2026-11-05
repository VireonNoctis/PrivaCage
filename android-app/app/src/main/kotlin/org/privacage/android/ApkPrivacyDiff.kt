package org.privacage.android

internal data class ApkExportedComponentChange(
    val before: ExportedApkComponent,
    val after: ExportedApkComponent
)

internal data class ApkTrackerIndicatorChange(
    val before: ApkTrackerIndicatorFinding,
    val after: ApkTrackerIndicatorFinding
)

internal enum class ApkSigningCertificateContinuity {
    UNCHANGED,
    AUTHORIZED_ROTATION,
    POSSIBLE_DOWNGRADE,
    LINEAGE_REGRESSION,
    SIGNER_MISMATCH,
    SIGNER_MODEL_CHANGED,
    UNKNOWN
}

internal data class ApkPrivacyDiffReport(
    val baseline: ApkManifestAuditReport,
    val candidate: ApkManifestAuditReport,
    val trackerCatalogSha256: String,
    val signingCertificateContinuity: ApkSigningCertificateContinuity,
    val addedPermissions: List<ApkPermissionFinding>,
    val removedPermissions: List<ApkPermissionFinding>,
    val addedExportedComponents: List<ExportedApkComponent>,
    val removedExportedComponents: List<ExportedApkComponent>,
    val changedExportedComponents: List<ApkExportedComponentChange>,
    val addedTrackerIndicators: List<ApkTrackerIndicatorFinding>,
    val removedTrackerIndicators: List<ApkTrackerIndicatorFinding>,
    val changedTrackerIndicators: List<ApkTrackerIndicatorChange>
)

/**
 * Compares two static APK audit reports. A match is a difference in declarations or embedded
 * strings only; this class does not infer runtime collection, maliciousness, or safety.
 */
internal object ApkPrivacyDiff {
    fun compare(
        baseline: ApkManifestAuditReport,
        candidate: ApkManifestAuditReport,
        trackerCatalogSha256: String
    ): ApkPrivacyDiffReport {
        require(baseline.packageName == candidate.packageName) {
            "Selected APKs have different package names. Choose two versions of the same app."
        }
        require(trackerCatalogSha256.matches(Regex("^[0-9a-f]{64}$"))) {
            "The bundled tracker catalog fingerprint is unavailable or invalid."
        }

        val baselinePermissions = baseline.permissions.associateBy { it.permissionName }
        val candidatePermissions = candidate.permissions.associateBy { it.permissionName }
        val baselineComponents = baseline.exportedComponents.associateBy {
            componentKey(it.kind, it.className)
        }
        val candidateComponents = candidate.exportedComponents.associateBy {
            componentKey(it.kind, it.className)
        }
        val baselineIndicators = baseline.trackerScan.findings.associateBy(::indicatorKey)
        val candidateIndicators = candidate.trackerScan.findings.associateBy(::indicatorKey)

        return ApkPrivacyDiffReport(
            baseline = baseline,
            candidate = candidate,
            trackerCatalogSha256 = trackerCatalogSha256,
            signingCertificateContinuity = compareSigningCertificateContinuity(baseline, candidate),
            addedPermissions = candidate.permissions
                .filter { it.permissionName !in baselinePermissions }
                .sortedBy { it.permissionName },
            removedPermissions = baseline.permissions
                .filter { it.permissionName !in candidatePermissions }
                .sortedBy { it.permissionName },
            addedExportedComponents = candidate.exportedComponents
                .filter { componentKey(it.kind, it.className) !in baselineComponents }
                .sortedWith(compareBy<ExportedApkComponent> { it.kind }.thenBy { it.className }),
            removedExportedComponents = baseline.exportedComponents
                .filter { componentKey(it.kind, it.className) !in candidateComponents }
                .sortedWith(compareBy<ExportedApkComponent> { it.kind }.thenBy { it.className }),
            changedExportedComponents = baselineComponents.keys
                .intersect(candidateComponents.keys)
                .sorted()
                .mapNotNull { key ->
                    val before = baselineComponents.getValue(key)
                    val after = candidateComponents.getValue(key)
                    if (before == after) null else ApkExportedComponentChange(before, after)
                },
            addedTrackerIndicators = candidateIndicators
                .filterKeys { it !in baselineIndicators }
                .values
                .sortedWith(indicatorOrdering),
            removedTrackerIndicators = baselineIndicators
                .filterKeys { it !in candidateIndicators }
                .values
                .sortedWith(indicatorOrdering),
            changedTrackerIndicators = baselineIndicators.keys
                .intersect(candidateIndicators.keys)
                .sorted()
                .mapNotNull { key ->
                    val before = baselineIndicators.getValue(key)
                    val after = candidateIndicators.getValue(key)
                    if (before == after) null else ApkTrackerIndicatorChange(before, after)
                }
        )
    }

    private fun compareSigningCertificateContinuity(
        baseline: ApkManifestAuditReport,
        candidate: ApkManifestAuditReport
    ): ApkSigningCertificateContinuity {
        val baselineStatus = baseline.signingCertificateHistoryStatus
        val candidateStatus = candidate.signingCertificateHistoryStatus

        if (baselineStatus == ApkSigningCertificateHistoryStatus.PLATFORM_UNSUPPORTED ||
            baselineStatus == ApkSigningCertificateHistoryStatus.METADATA_UNAVAILABLE ||
            candidateStatus == ApkSigningCertificateHistoryStatus.PLATFORM_UNSUPPORTED ||
            candidateStatus == ApkSigningCertificateHistoryStatus.METADATA_UNAVAILABLE
        ) {
            return ApkSigningCertificateContinuity.UNKNOWN
        }

        if (baselineStatus == ApkSigningCertificateHistoryStatus.MULTIPLE_SIGNERS ||
            candidateStatus == ApkSigningCertificateHistoryStatus.MULTIPLE_SIGNERS
        ) {
            if (baselineStatus != candidateStatus) {
                return ApkSigningCertificateContinuity.SIGNER_MODEL_CHANGED
            }
            return if (baseline.signingCertificateSha256 == candidate.signingCertificateSha256) {
                ApkSigningCertificateContinuity.UNCHANGED
            } else {
                ApkSigningCertificateContinuity.SIGNER_MISMATCH
            }
        }

        val baselineHistory = baseline.signingCertificateHistorySha256
        val candidateHistory = candidate.signingCertificateHistorySha256
        if (baselineHistory.isEmpty() || candidateHistory.isEmpty()) {
            return ApkSigningCertificateContinuity.UNKNOWN
        }
        if (baseline.signingCertificateSha256 != listOf(baselineHistory.last()) ||
            candidate.signingCertificateSha256 != listOf(candidateHistory.last())
        ) {
            return ApkSigningCertificateContinuity.SIGNER_MISMATCH
        }
        if (baselineHistory == candidateHistory &&
            baseline.signingCertificateSha256 == candidate.signingCertificateSha256
        ) {
            return ApkSigningCertificateContinuity.UNCHANGED
        }

        val candidateExtendsBaseline = candidateHistory.size > baselineHistory.size &&
            candidateHistory.take(baselineHistory.size) == baselineHistory
        if (candidateExtendsBaseline && candidate.versionCode > baseline.versionCode) {
            return ApkSigningCertificateContinuity.AUTHORIZED_ROTATION
        }

        val candidateIsEarlierLineage = baselineHistory.size > candidateHistory.size &&
            baselineHistory.take(candidateHistory.size) == candidateHistory
        if (candidateIsEarlierLineage && candidate.versionCode < baseline.versionCode) {
            return ApkSigningCertificateContinuity.POSSIBLE_DOWNGRADE
        }
        if (candidateIsEarlierLineage) {
            return ApkSigningCertificateContinuity.LINEAGE_REGRESSION
        }
        return ApkSigningCertificateContinuity.SIGNER_MISMATCH
    }

    private fun componentKey(kind: String, className: String): String = "$kind\u0000$className"

    private fun indicatorKey(finding: ApkTrackerIndicatorFinding): String =
        listOf(finding.recordId, finding.indicatorType, finding.indicator).joinToString("\u0000")

    private val indicatorOrdering =
        compareBy<ApkTrackerIndicatorFinding> { it.recordId }
            .thenBy { it.indicatorType }
            .thenBy { it.indicator }
}
