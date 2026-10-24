package org.privacage.android

import android.content.pm.ComponentInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import org.privacage.audit.PermissionRiskClassifier
import org.privacage.audit.PermissionReview
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.security.MessageDigest

internal data class ApkPermissionFinding(
    val permissionName: String,
    val review: PermissionReview
)

internal data class ExportedApkComponent(
    val kind: String,
    val className: String,
    val enabled: Boolean,
    val requiredPermission: String?
)

internal data class ApkManifestAuditReport(
    val packageName: String,
    val versionName: String?,
    val versionCode: Long,
    val targetSdkVersion: Int?,
    val fileSizeBytes: Long,
    val sha256: String,
    val signingCertificateSha256: List<String>,
    val permissions: List<ApkPermissionFinding>,
    val exportedComponents: List<ExportedApkComponent>,
    val trackerScan: ApkTrackerScanReport
)

/**
 * Reads an explicitly selected APK with Android's package parser and scans bounded DEX byte strings.
 * It never installs or executes the archive; static declarations and strings are not runtime proof.
 */
internal class ApkManifestAuditor(
    private val packageManager: PackageManager
) {
    fun inspect(apkFile: File, trackerCatalog: List<TrackerSignature>): ApkManifestAuditReport {
        if (!apkFile.isFile || apkFile.length() !in 1..MAX_APK_BYTES.toLong()) {
            throw IOException("APK must be a readable file no larger than 100 MiB.")
        }

        val signingFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS or
            signingFlags
        val packageInfo = loadPackageInfo(apkFile.absolutePath, flags)
            ?: throw IOException("Android could not parse this file as an APK.")

        val permissions = packageInfo.requestedPermissions
            .orEmpty()
            .distinct()
            .sorted()
            .map { permission ->
                ApkPermissionFinding(permission, PermissionRiskClassifier.classify(permission))
            }

        val exportedComponents = buildList {
            packageInfo.activities.orEmpty().forEach {
                addIfExported("Activity", it, it.permission)
            }
            packageInfo.services.orEmpty().forEach {
                addIfExported("Service", it, it.permission)
            }
            packageInfo.receivers.orEmpty().forEach {
                addIfExported("Receiver", it, it.permission)
            }
            packageInfo.providers.orEmpty().forEach { provider ->
                val providerPermissions = listOfNotNull(
                    provider.readPermission?.takeIf(String::isNotBlank)?.let { "read=$it" },
                    provider.writePermission?.takeIf(String::isNotBlank)?.let { "write=$it" }
                ).joinToString(", ").ifEmpty { null }
                addIfExported("Provider", provider, providerPermissions)
            }
        }.sortedWith(compareBy<ExportedApkComponent> { it.kind }.thenBy { it.className })

        val trackerScan = ApkTrackerIndicatorScanner().scan(apkFile, trackerCatalog)

        @Suppress("DEPRECATION")
        val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.longVersionCode
        } else {
            packageInfo.versionCode.toLong()
        }

        return ApkManifestAuditReport(
            packageName = packageInfo.packageName,
            versionName = packageInfo.versionName,
            versionCode = versionCode,
            targetSdkVersion = packageInfo.applicationInfo?.targetSdkVersion,
            fileSizeBytes = apkFile.length(),
            sha256 = sha256(apkFile),
            signingCertificateSha256 = signingCertificateFingerprints(packageInfo),
            permissions = permissions,
            exportedComponents = exportedComponents,
            trackerScan = trackerScan
        )
    }

    @Suppress("DEPRECATION")
    private fun loadPackageInfo(path: String, flags: Int): PackageInfo? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            packageManager.getPackageArchiveInfo(path, flags)
        }

    private fun MutableList<ExportedApkComponent>.addIfExported(
        kind: String,
        component: ComponentInfo,
        requiredPermission: String?
    ) {
        if (!component.exported) return
        val name = component.name?.takeIf(String::isNotBlank) ?: return
        add(
            ExportedApkComponent(
                kind = kind,
                className = name,
                enabled = component.enabled,
                requiredPermission = requiredPermission
            )
        )
    }

    private fun signingCertificateFingerprints(packageInfo: PackageInfo): List<String> {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.signingInfo?.apkContentsSigners?.toList().orEmpty()
        } else {
            legacySignatures(packageInfo)
        }
        return signatures
            .map { CertificateFingerprint.sha256(it.toByteArray()) }
            .distinct()
            .sorted()
    }

    @Suppress("DEPRECATION")
    private fun legacySignatures(packageInfo: PackageInfo) =
        packageInfo.signatures?.toList().orEmpty()

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(HASH_BUFFER_BYTES)
        try {
            FileInputStream(file).use { input ->
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    digest.update(buffer, 0, count)
                }
            }
        } finally {
            buffer.fill(0)
        }

        val hexDigits = "0123456789abcdef"
        return buildString(64) {
            for (byte in digest.digest()) {
                val value = byte.toInt() and 0xff
                append(hexDigits[value ushr 4])
                append(hexDigits[value and 0x0f])
            }
        }
    }

    companion object {
        const val MAX_APK_BYTES = 100 * 1024 * 1024
        private const val HASH_BUFFER_BYTES = 8_192
    }
}
