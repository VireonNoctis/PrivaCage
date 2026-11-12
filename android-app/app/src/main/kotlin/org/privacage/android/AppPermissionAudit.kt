package org.privacage.android

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import org.json.JSONException
import org.json.JSONObject
import org.privacage.audit.PermissionChangeKind
import org.privacage.audit.PermissionGrantSnapshot
import java.io.IOException
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * Local audit of dangerous permissions declared by launcher-visible applications.
 *
 * Android package visibility intentionally limits this to apps discoverable through
 * the launcher intent. The optional comparison baseline stores only package names,
 * dangerous permission names, and grant booleans in an AES-GCM encrypted app-private preference.
 */
internal object AppPermissionAudit {
    internal data class BaselinePreferenceRead(
        val value: String?,
        val unreadable: Boolean,
        val warning: String?
    )

    internal fun readBaselinePreference(readValue: () -> String?): BaselinePreferenceRead =
        try {
            BaselinePreferenceRead(readValue(), unreadable = false, warning = null)
        } catch (exception: ClassCastException) {
            BaselinePreferenceRead(
                value = null,
                unreadable = true,
                warning = "The saved permission baseline has an unexpected stored type and has been preserved."
            )
        } catch (exception: IOException) {
            BaselinePreferenceRead(
                value = null,
                unreadable = true,
                warning = "The saved encrypted permission baseline could not be authenticated or read and has been preserved: " +
                    (exception.message ?: exception.javaClass.simpleName)
            )
        }

    /**
     * Returns null when Android cannot resolve the declared permission. Unknown metadata is
     * not evidence that the permission is non-dangerous.
     */
    internal fun isDangerousPermission(readProtectionLevel: () -> Int): Boolean? =
        try {
            val protectionLevel = readProtectionLevel()
            (protectionLevel and PermissionInfo.PROTECTION_MASK_BASE) ==
                PermissionInfo.PROTECTION_DANGEROUS
        } catch (exception: PackageManager.NameNotFoundException) {
            null
        } catch (exception: SecurityException) {
            null
        }

    /** Returns null when Android does not expose the matching grant flag. */
    internal fun requestedPermissionGrantState(flags: IntArray?, index: Int): Boolean? =
        flags?.getOrNull(index)?.let { permissionFlags ->
            (permissionFlags and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        }

    internal fun isCompleteScan(
        skippedPackages: Int,
        unavailablePermissionClassifications: Int,
        unavailableGrantStates: Int,
        incompletePermissionInventories: Int = 0
    ): Boolean =
        skippedPackages == 0 &&
            unavailablePermissionClassifications == 0 &&
            unavailableGrantStates == 0 &&
            incompletePermissionInventories == 0

    internal data class BaselinePreparation(
        val encoded: String?,
        val failureReason: String?
    )

    internal fun prepareBaselineForComparison(
        snapshot: PermissionGrantSnapshot,
        capturedAt: Instant
    ): BaselinePreparation =
        try {
            BaselinePreparation(encoded = encodeBaseline(snapshot, capturedAt), failureReason = null)
        } catch (exception: IOException) {
            BaselinePreparation(
                encoded = null,
                failureReason = exception.message ?: "The snapshot exceeds supported baseline limits."
            )
        }

    internal fun canCompareBaseline(
        skippedPackages: Int,
        unavailablePermissionClassifications: Int,
        unavailableGrantStates: Int,
        baselinePreparation: BaselinePreparation,
        incompletePermissionInventories: Int = 0
    ): Boolean =
        isCompleteScan(
            skippedPackages,
            unavailablePermissionClassifications,
            unavailableGrantStates,
            incompletePermissionInventories
        ) && baselinePreparation.encoded != null

    private const val MAX_APPS_IN_REPORT = 60
    private const val MAX_CHANGES_IN_REPORT = 100
    private const val PREFERENCES_NAME = "privacage_permission_audit"
    private const val KEY_BASELINE = "dangerous_permission_baseline_v1"
    private const val KEY_BASELINE_ENCRYPTED = "dangerous_permission_baseline_encrypted_v1"
    private const val KEY_ALIAS = "org.privacage.android.permission-baseline.aes-gcm.v1"
    private const val AAD_LABEL = "permission-audit-baseline"
    private const val BASELINE_SCHEMA_VERSION = 2
    private const val MAX_BASELINE_BYTES = 4 * 1024 * 1024
    private const val MAX_BASELINE_PACKAGES = 2_000
    private const val MAX_PERMISSIONS_PER_PACKAGE = 256
    private const val MAX_DECLARED_PERMISSIONS_PER_PACKAGE = 512
    private const val MAX_DECLARED_PERMISSIONS_PER_SCAN = 50_000

    internal fun isWithinBaselinePackageLimit(packageCount: Int): Boolean =
        packageCount in 0..MAX_BASELINE_PACKAGES

    internal fun permissionDeclarationsFitLimits(
        packageDeclarationCount: Int,
        totalDeclarationCount: Int
    ): Boolean =
        packageDeclarationCount in 0..MAX_DECLARED_PERMISSIONS_PER_PACKAGE &&
            totalDeclarationCount in 0..MAX_DECLARED_PERMISSIONS_PER_SCAN &&
            packageDeclarationCount <= MAX_DECLARED_PERMISSIONS_PER_SCAN - totalDeclarationCount

    private val PACKAGE_NAME_PATTERN = Regex("^[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+$")
    private val PERMISSION_NAME_PATTERN = Regex("^[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)*$")

    fun clearBaseline(context: Context): Boolean =
        AndroidSensitivePreferenceVault.clear(
            context,
            PREFERENCES_NAME,
            KEY_BASELINE_ENCRYPTED,
            setOf(KEY_BASELINE)
        )

    fun scan(context: Context): String {
        val packageManager = context.packageManager
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val launchers = try {
            packageManager.queryIntentActivities(launcherIntent, 0)
        } catch (exception: RuntimeException) {
            return "Permission audit failed: " + (exception.message ?: exception.javaClass.simpleName)
        }

        val packageNames = launchers.mapNotNull { it.activityInfo?.packageName }
            .distinct()
            .sorted()

        if (packageNames.isEmpty()) {
            return "Android returned no launcher-visible applications. This may be a restricted profile or OEM-specific package-visibility behavior."
        }
        if (!isWithinBaselinePackageLimit(packageNames.size)) {
            return "Permission audit was not run because Android exposed ${packageNames.size} launcher-visible applications, above the supported limit of $MAX_BASELINE_PACKAGES. The existing encrypted baseline was preserved; no comparison or replacement was attempted."
        }

        var inspected = 0
        var skipped = 0
        var unavailablePermissionClassifications = 0
        var unavailableGrantStates = 0
        var oversizedPermissionPackages = 0
        var totalDeclaredPermissions = 0
        var permissionScanStoppedAtTotalLimit = false
        val rows = mutableListOf<String>()
        val labelsByPackage = mutableMapOf<String, String>()
        val observedPermissions = linkedMapOf<String, Map<String, Boolean>>()

        for ((packageIndex, packageName) in packageNames.withIndex()) {
            val packageInfo = try {
                packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            } catch (exception: PackageManager.NameNotFoundException) {
                skipped++
                continue
            } catch (exception: SecurityException) {
                skipped++
                continue
            }

            inspected++
            val label = try {
                packageInfo.applicationInfo?.let { packageManager.getApplicationLabel(it).toString() } ?: packageName
            } catch (exception: RuntimeException) {
                packageName
            }
            labelsByPackage[packageName] = label

            val requested = packageInfo.requestedPermissions
            if (requested == null) {
                observedPermissions[packageName] = emptyMap()
                continue
            }
            if (requested.size > MAX_DECLARED_PERMISSIONS_PER_PACKAGE) {
                oversizedPermissionPackages++
                continue
            }
            if (!permissionDeclarationsFitLimits(requested.size, totalDeclaredPermissions)) {
                permissionScanStoppedAtTotalLimit = true
                break
            }
            totalDeclaredPermissions += requested.size

            val flags = packageInfo.requestedPermissionsFlags
            val perPackage = linkedMapOf<String, Boolean>()
            val sensitive = mutableListOf<String>()
            requested.forEachIndexed { index, permission ->
                val isDangerous = isDangerousPermission {
                    packageManager.getPermissionInfo(permission, 0).protectionLevel
                }
                if (isDangerous == null) {
                    unavailablePermissionClassifications++
                    return@forEachIndexed
                }
                if (!isDangerous) return@forEachIndexed

                val granted = requestedPermissionGrantState(flags, index)
                if (granted == null) {
                    unavailableGrantStates++
                    sensitive += permission.substringAfterLast('.') + " — GRANT STATE UNAVAILABLE"
                    return@forEachIndexed
                }
                perPackage[permission] = granted
                sensitive += permission.substringAfterLast('.') +
                    if (granted) " — GRANTED" else " — NOT CURRENTLY GRANTED"
            }
            observedPermissions[packageName] = perPackage

            if (sensitive.isNotEmpty()) {
                rows += label + " (" + packageName + ")\n" +
                    sensitive.sorted().joinToString("\n") { "  • " + it }
            }
        }

        val output = StringBuilder()
        output.append("Launcher-visible apps inspected: ").append(inspected)
            .append("; apps with declared dangerous permissions: ").append(rows.size)
            .append("; packages skipped: ").append(skipped).append("\n\n")

        if (rows.isEmpty()) {
            if (unavailablePermissionClassifications > 0 || oversizedPermissionPackages > 0 || permissionScanStoppedAtTotalLimit) {
                output.append("No dangerous-permission conclusion is available for the full launcher inventory because some declarations could not be fully inspected.")
            } else {
                output.append("No dangerous runtime permissions were found in the requested-permission declarations of the inspected launcher apps.")
            }
        } else {
            rows.take(MAX_APPS_IN_REPORT).forEachIndexed { index, row ->
                if (index > 0) output.append("\n\n")
                output.append(row)
            }
            if (rows.size > MAX_APPS_IN_REPORT) {
                output.append("\n\nReport limited to ").append(MAX_APPS_IN_REPORT)
                    .append(" apps; ").append(rows.size - MAX_APPS_IN_REPORT).append(" additional apps omitted.")
            }
        }

        if (unavailablePermissionClassifications > 0) {
            output.append("\n\nPermission classification unavailable for ")
                .append(unavailablePermissionClassifications)
                .append(" declared permission(s); these were not treated as non-dangerous.")
        }
        if (unavailableGrantStates > 0) {
            output.append("\nGrant state unavailable for ")
                .append(unavailableGrantStates)
                .append(" declared dangerous permission(s); these were not treated as denied.")
        }

        if (oversizedPermissionPackages > 0) {
            output.append("\n\nPermission declarations were not inspected for ")
                .append(oversizedPermissionPackages)
                .append(" app(s) because each exceeded the ")
                .append(MAX_DECLARED_PERMISSIONS_PER_PACKAGE)
                .append("-declaration per-app safety limit.")
        }
        if (permissionScanStoppedAtTotalLimit) {
            output.append("\n\nPermission inventory stopped at the ")
                .append(MAX_DECLARED_PERMISSIONS_PER_SCAN)
                .append("-declaration scan limit; remaining launcher-visible apps were not inspected.")
        }

        val incompletePermissionInventories = oversizedPermissionPackages + if (permissionScanStoppedAtTotalLimit) 1 else 0
        val currentSnapshot = PermissionGrantSnapshot(observedPermissions)
        val scanCapturedAt = Instant.now()
        val scanEvidenceComplete = isCompleteScan(
            skipped,
            unavailablePermissionClassifications,
            unavailableGrantStates,
            incompletePermissionInventories
        )
        val baselinePreparation = prepareBaselineForComparison(currentSnapshot, scanCapturedAt)
        output.append("\n\nPERMISSION SNAPSHOT COMPARISON (LOCAL ONLY)\n")
        if (!canCompareBaseline(
                skipped,
                unavailablePermissionClassifications,
                unavailableGrantStates,
                baselinePreparation,
                incompletePermissionInventories
            )
        ) {
            val incompleteReasons = mutableListOf<String>()
            if (skipped > 0) incompleteReasons += "$skipped package(s) could not be inspected"
            if (unavailablePermissionClassifications > 0) {
                incompleteReasons += "$unavailablePermissionClassifications permission declaration(s) could not be classified"
            }
            if (unavailableGrantStates > 0) {
                incompleteReasons += "$unavailableGrantStates dangerous permission grant state(s) were unavailable"
            }
            if (incompletePermissionInventories > 0) {
                incompleteReasons += "one or more permission inventories exceeded the scan safety limits"
            }
            if (scanEvidenceComplete && baselinePreparation.encoded == null) {
                incompleteReasons += "the current snapshot exceeds supported encrypted-baseline limits: " +
                    (baselinePreparation.failureReason ?: "encoding was unavailable")
            }
            output.append("Comparison was not run and the saved baseline was not changed because ")
                .append(incompleteReasons.joinToString("; "))
                .append(". This avoids treating unknown permission evidence as a real change.")
        } else {
            val encodedBaseline = baselinePreparation.encoded
                ?: throw IOException("Baseline comparison was allowed without an encoded snapshot.")
            val baselineRead = readBaselinePreference {
                AndroidSensitivePreferenceVault.read(
                    context = context,
                    preferencesName = PREFERENCES_NAME,
                    encryptedKey = KEY_BASELINE_ENCRYPTED,
                    keyAlias = KEY_ALIAS,
                    aadLabel = AAD_LABEL,
                    defaultValue = null,
                    maximumPlaintextBytes = MAX_BASELINE_BYTES,
                    legacyKeys = setOf(KEY_BASELINE),
                    legacyValue = {
                        context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
                            .getString(KEY_BASELINE, null)
                            ?: throw IOException("The legacy permission baseline has no readable value.")
                    },
                    validateValue = { decodeBaselineRecord(it) }
                )
            }
            val rawBaseline = baselineRead.value
            var baselineWarning: String? = baselineRead.warning
            var preserveUnreadableBaseline = baselineRead.unreadable
            val previousRecord = if (rawBaseline == null) {
                null
            } else {
                try {
                    decodeBaselineRecord(rawBaseline)
                } catch (exception: Exception) {
                    preserveUnreadableBaseline = true
                    baselineWarning = "The saved baseline is unreadable and has been preserved: " +
                        (exception.message ?: exception.javaClass.simpleName)
                    null
                }
            }
            val previousSnapshot = previousRecord?.snapshot

            if (previousSnapshot == null) {
                if (preserveUnreadableBaseline) {
                    output.append("Comparison was not run because the saved baseline is unreadable; the current scan was not saved as a replacement baseline.")
                } else {
                    output.append("No usable previous snapshot was available; this scan completed at ")
                        .append(scanCapturedAt).append(" (device clock).")
                }
                if (baselineWarning != null) output.append("\n").append(baselineWarning)
            } else {
                output.append("Baseline captured at ")
                    .append(previousRecord?.capturedAt?.toString() ?: "unknown (legacy schema v1)")
                    .append("; current scan completed at ").append(scanCapturedAt)
                    .append(" (device clock). The exact time of any change is unknown.\n")
                val diff = currentSnapshot.compare(previousSnapshot)
                if (diff.changes.isEmpty() &&
                    diff.newlyObservedPackages.isEmpty() &&
                    diff.noLongerObservedPackages.isEmpty()) {
                    output.append("No changes were found in the comparable launcher-visible dangerous-permission declarations and grant states.")
                } else {
                    if (diff.changes.isNotEmpty()) {
                        output.append("Permission changes (").append(diff.changes.size).append("):")
                        diff.changes.take(MAX_CHANGES_IN_REPORT).forEach { change ->
                            val appLabel = labelsByPackage[change.packageName] ?: change.packageName
                            output.append("\n[")
                            output.append(
                                when (change.kind) {
                                    PermissionChangeKind.NEWLY_REQUESTED -> "NEWLY REQUESTED"
                                    PermissionChangeKind.NO_LONGER_REQUESTED -> "NO LONGER REQUESTED"
                                    PermissionChangeKind.NEWLY_GRANTED -> "NEWLY GRANTED"
                                    PermissionChangeKind.GRANT_REVOKED -> "GRANT REVOKED"
                                }
                            )
                            output.append("] ").append(appLabel).append(" (").append(change.packageName).append(") — ")
                                .append(change.permissionName.substringAfterLast('.'))
                            when (change.kind) {
                                PermissionChangeKind.NEWLY_REQUESTED -> output.append(
                                    if (change.currentlyGranted == true) "; declared and currently granted"
                                    else "; declared but not currently granted"
                                )
                                PermissionChangeKind.NO_LONGER_REQUESTED -> output.append(
                                    if (change.previouslyGranted == true) "; previously granted, no longer declared"
                                    else "; previously declared, no longer requested"
                                )
                                PermissionChangeKind.NEWLY_GRANTED -> output.append("; grant changed from off to on")
                                PermissionChangeKind.GRANT_REVOKED -> output.append("; grant changed from on to off")
                            }
                        }
                        if (diff.changes.size > MAX_CHANGES_IN_REPORT) {
                            output.append("\n… ").append(diff.changes.size - MAX_CHANGES_IN_REPORT)
                                .append(" additional permission changes omitted from this view.")
                        }
                    } else {
                        output.append("No permission declaration or grant changes were found.")
                    }
                    if (diff.newlyObservedPackages.isNotEmpty()) {
                        output.append("\n\nNewly observed launcher package(s): ")
                            .append(diff.newlyObservedPackages.joinToString(", "))
                    }
                    if (diff.noLongerObservedPackages.isNotEmpty()) {
                        output.append("\n\nPackages no longer visible in the launcher scan: ")
                            .append(diff.noLongerObservedPackages.joinToString(", "))
                            .append(". No permission revocation is inferred for packages that left the scan.")
                    }
                }
            }

            if (preserveUnreadableBaseline) {
                output.append("\nSaved baseline was not replaced. Clear it explicitly if you want to start a new comparison history.")
            } else {
                try {
                    AndroidSensitivePreferenceVault.write(
                        context = context,
                        preferencesName = PREFERENCES_NAME,
                        encryptedKey = KEY_BASELINE_ENCRYPTED,
                        keyAlias = KEY_ALIAS,
                        aadLabel = AAD_LABEL,
                        plaintext = encodedBaseline,
                        maximumPlaintextBytes = MAX_BASELINE_BYTES,
                        legacyKeys = setOf(KEY_BASELINE),
                        validateValue = { decodeBaselineRecord(it) }
                    )
                    output.append("\nSaved this completed scan as the next encrypted local comparison baseline.")
                } catch (exception: Exception) {
                    output.append("\nBaseline write failed: ")
                        .append(exception.message ?: exception.javaClass.simpleName)
                }
            }
        }

        output.append("\n\nImportant limits: this reads manifest declarations and current grant flags, not live sensor use or data transmission. ")
            .append("Apps without launcher activities, many headless system components, privileged Google/Samsung services, work-profile apps, and hidden packages may be absent. ")
            .append("A granted permission does not prove it was used; a missing permission does not prove an app collects no data. ")
            .append("The saved comparison baseline is local and removable from the dashboard; PrivaCage does not silently revoke permissions.")
        return output.toString()
    }

    internal data class DecodedBaseline(
        val snapshot: PermissionGrantSnapshot,
        val capturedAt: Instant?
    )

    internal fun encodeBaseline(snapshot: PermissionGrantSnapshot, capturedAt: Instant): String {
        val sortedPackages = snapshot.packages.toSortedMap()
        if (sortedPackages.size > MAX_BASELINE_PACKAGES) {
            throw IOException("Baseline package count exceeds the supported limit")
        }

        // Validate and estimate the compact JSON size before allocating JSONObject trees.
        // Package and permission keys are restricted to ASCII-safe characters, so this estimate
        // is exact for the serialized representation below.
        val prefix = """{"schema_version":$BASELINE_SCHEMA_VERSION,"captured_at":"$capturedAt","packages":{"""
        var estimatedBytes = prefix.length.toLong() + 2L
        sortedPackages.entries.forEachIndexed { packageIndex, (packageName, permissions) ->
            if (packageName.isBlank() || packageName.length > 255 ||
                !PACKAGE_NAME_PATTERN.matches(packageName)
            ) {
                throw IOException("Snapshot contains an invalid package name")
            }
            if (permissions.size > MAX_PERMISSIONS_PER_PACKAGE) {
                throw IOException("Baseline permission count exceeds the supported limit for $packageName")
            }

            if (packageIndex > 0) estimatedBytes++
            estimatedBytes += packageName.length.toLong() + 5L
            permissions.toSortedMap().entries.forEachIndexed { permissionIndex, (permission, granted) ->
                if (permission.isBlank() || permission.length > 255 ||
                    !PERMISSION_NAME_PATTERN.matches(permission)
                ) {
                    throw IOException("Snapshot contains an invalid permission name for $packageName")
                }
                if (permissionIndex > 0) estimatedBytes++
                estimatedBytes += permission.length.toLong() + if (granted) 7L else 8L
                if (estimatedBytes > MAX_BASELINE_BYTES) {
                    throw IOException("Permission baseline exceeds the 4 MiB safety limit")
                }
            }
            estimatedBytes++
            if (estimatedBytes > MAX_BASELINE_BYTES) {
                throw IOException("Permission baseline exceeds the 4 MiB safety limit")
            }
        }

        val packages = JSONObject()
        sortedPackages.forEach { (packageName, permissions) ->
            val permissionObject = JSONObject()
            permissions.toSortedMap().forEach { (permission, granted) ->
                permissionObject.put(permission, granted)
            }
            packages.put(packageName, permissionObject)
        }
        val encoded = JSONObject()
            .put("schema_version", BASELINE_SCHEMA_VERSION)
            .put("captured_at", capturedAt.toString())
            .put("packages", packages)
            .toString()
        if (encoded.toByteArray(Charsets.UTF_8).size > MAX_BASELINE_BYTES) {
            throw IOException("Permission baseline exceeds the 4 MiB safety limit")
        }
        return encoded
    }

    internal fun decodeBaseline(text: String): PermissionGrantSnapshot =
        decodeBaselineRecord(text).snapshot

    internal fun decodeBaselineRecord(text: String): DecodedBaseline {
        if (text.length > MAX_BASELINE_BYTES ||
            text.toByteArray(Charsets.UTF_8).size > MAX_BASELINE_BYTES
        ) {
            throw IOException("Permission baseline exceeds the 4 MiB safety limit")
        }
        StrictJsonKeyScanner.validate(text, "Permission baseline")
        val root = try {
            JSONObject(text)
        } catch (exception: JSONException) {
            throw IOException("Baseline is not valid JSON", exception)
        }
        val schemaVersion = root.opt("schema_version")
        if (schemaVersion !is Int || schemaVersion !in 1..BASELINE_SCHEMA_VERSION) {
            throw IOException("Baseline schema version is invalid or unsupported")
        }
        val expectedKeys = if (schemaVersion == 1) {
            setOf("schema_version", "packages")
        } else {
            setOf("schema_version", "captured_at", "packages")
        }
        val rootKeys = root.keys().asSequence().toSet()
        if (rootKeys != expectedKeys) {
            throw IOException("Baseline contains missing or unsupported top-level fields")
        }
        if (root.opt("packages") !is JSONObject) {
            throw IOException("Baseline package map is invalid")
        }

        val capturedAt = if (schemaVersion == 1) {
            null
        } else {
            val rawTimestamp = root.opt("captured_at") as? String
                ?: throw IOException("Baseline capture timestamp is invalid")
            val parsedTimestamp = try {
                Instant.parse(rawTimestamp)
            } catch (exception: DateTimeParseException) {
                throw IOException("Baseline capture timestamp is invalid", exception)
            }
            if (parsedTimestamp.toString() != rawTimestamp) {
                throw IOException("Baseline capture timestamp is not in canonical UTC form")
            }
            parsedTimestamp
        }

        val packagesObject = root.getJSONObject("packages")
        if (packagesObject.length() > MAX_BASELINE_PACKAGES) {
            throw IOException("Baseline package count exceeds the supported limit")
        }
        val packages = linkedMapOf<String, Map<String, Boolean>>()
        val packageIterator = packagesObject.keys()
        while (packageIterator.hasNext()) {
            val packageName = packageIterator.next()
            if (packageName.isBlank() || packageName.length > 255) {
                throw IOException("Baseline contains an invalid package name")
            }
            if (!PACKAGE_NAME_PATTERN.matches(packageName)) {
                throw IOException("Baseline contains an invalid package name")
            }
            val permissionsObject = packagesObject.opt(packageName) as? JSONObject
                ?: throw IOException("Baseline permission map is invalid for " + packageName)
            if (permissionsObject.length() > MAX_PERMISSIONS_PER_PACKAGE) {
                throw IOException("Baseline permission count exceeds the supported limit for " + packageName)
            }
            val permissions = linkedMapOf<String, Boolean>()
            val permissionIterator = permissionsObject.keys()
            while (permissionIterator.hasNext()) {
                val permission = permissionIterator.next()
                val granted = permissionsObject.opt(permission) as? Boolean
                    ?: throw IOException("Baseline grant flag is invalid for " + packageName)
                if (!PERMISSION_NAME_PATTERN.matches(permission) || permission.length > 255) {
                    throw IOException("Baseline contains an invalid permission name")
                }
                permissions[permission] = granted
            }
            packages[packageName] = permissions
        }
        return DecodedBaseline(PermissionGrantSnapshot(packages), capturedAt)
    }
}
