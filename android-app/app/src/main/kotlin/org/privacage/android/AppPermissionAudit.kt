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

/**
 * Local audit of dangerous permissions declared by launcher-visible applications.
 *
 * Android package visibility intentionally limits this to apps discoverable through
 * the launcher intent. The optional comparison baseline stores only package names,
 * dangerous permission names, and grant booleans in app-private preferences.
 */
internal object AppPermissionAudit {
    private const val MAX_APPS_IN_REPORT = 60
    private const val MAX_CHANGES_IN_REPORT = 100
    private const val PREFERENCES_NAME = "privacage_permission_audit"
    private const val KEY_BASELINE = "dangerous_permission_baseline_v1"
    private const val BASELINE_SCHEMA_VERSION = 1
    private const val MAX_BASELINE_BYTES = 4 * 1024 * 1024

    fun clearBaseline(context: Context): Boolean =
        context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_BASELINE)
            .commit()

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

        var inspected = 0
        var skipped = 0
        val rows = mutableListOf<String>()
        val labelsByPackage = mutableMapOf<String, String>()
        val observedPermissions = linkedMapOf<String, Map<String, Boolean>>()

        for (packageName in packageNames) {
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

            val flags = packageInfo.requestedPermissionsFlags
            val perPackage = linkedMapOf<String, Boolean>()
            val sensitive = mutableListOf<String>()
            requested.forEachIndexed { index, permission ->
                val isDangerous = try {
                    val info = packageManager.getPermissionInfo(permission, 0)
                    (info.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE) ==
                        PermissionInfo.PROTECTION_DANGEROUS
                } catch (exception: PackageManager.NameNotFoundException) {
                    false
                } catch (exception: SecurityException) {
                    false
                }
                if (!isDangerous) return@forEachIndexed

                val granted = flags?.getOrNull(index)
                    ?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) == PackageInfo.REQUESTED_PERMISSION_GRANTED
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
            output.append("No dangerous runtime permissions were found in the requested-permission declarations of the inspected launcher apps.")
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

        val currentSnapshot = PermissionGrantSnapshot(observedPermissions)
        output.append("\n\nPERMISSION SNAPSHOT COMPARISON (LOCAL ONLY)\n")
        if (skipped > 0) {
            output.append("Comparison was not run and the saved baseline was not changed because ")
                .append(skipped).append(" package(s) could not be inspected. This avoids treating an incomplete scan as a real permission change.")
        } else {
            val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
            val rawBaseline = preferences.getString(KEY_BASELINE, null)
            var baselineWarning: String? = null
            var preserveUnreadableBaseline = false
            val previousSnapshot = if (rawBaseline == null) {
                null
            } else {
                try {
                    decodeBaseline(rawBaseline)
                } catch (exception: Exception) {
                    preserveUnreadableBaseline = true
                    baselineWarning = "The saved baseline is unreadable and has been preserved: " +
                        (exception.message ?: exception.javaClass.simpleName)
                    null
                }
            }

            if (previousSnapshot == null) {
                if (preserveUnreadableBaseline) {
                    output.append("Comparison was not run because the saved baseline is unreadable; the current scan was not saved as a replacement baseline.")
                } else {
                    output.append("No usable previous snapshot was available; this completed scan establishes the next comparison baseline.")
                }
                if (baselineWarning != null) output.append("\n").append(baselineWarning)
            } else {
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
                    val saved = preferences.edit()
                        .putString(KEY_BASELINE, encodeBaseline(currentSnapshot))
                        .commit()
                    if (!saved) {
                        output.append("\nBaseline write failed: Android did not confirm the local preference write.")
                    }
                } catch (exception: RuntimeException) {
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

    private fun encodeBaseline(snapshot: PermissionGrantSnapshot): String {
        val packages = JSONObject()
        snapshot.packages.toSortedMap().forEach { (packageName, permissions) ->
            val permissionObject = JSONObject()
            permissions.toSortedMap().forEach { (permission, granted) ->
                permissionObject.put(permission, granted)
            }
            packages.put(packageName, permissionObject)
        }
        return JSONObject()
            .put("schema_version", BASELINE_SCHEMA_VERSION)
            .put("packages", packages)
            .toString()
    }

    internal fun decodeBaseline(text: String): PermissionGrantSnapshot {
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
        val rootKeys = root.keys().asSequence().toSet()
        if (rootKeys != setOf("schema_version", "packages")) {
            throw IOException("Baseline contains missing or unsupported top-level fields")
        }
        val schemaVersion = root.opt("schema_version") as? Number
        if (schemaVersion == null ||
            schemaVersion.toDouble() != BASELINE_SCHEMA_VERSION.toDouble() ||
            root.opt("packages") !is JSONObject) {
            throw IOException("Baseline schema version or package map is invalid")
        }
        val packagesObject = root.getJSONObject("packages")
        val packages = linkedMapOf<String, Map<String, Boolean>>()
        val packageIterator = packagesObject.keys()
        while (packageIterator.hasNext()) {
            val packageName = packageIterator.next()
            if (packageName.isBlank() || packageName.length > 255) {
                throw IOException("Baseline contains an invalid package name")
            }
            val permissionsObject = packagesObject.opt(packageName) as? JSONObject
                ?: throw IOException("Baseline permission map is invalid for " + packageName)
            val permissions = linkedMapOf<String, Boolean>()
            val permissionIterator = permissionsObject.keys()
            while (permissionIterator.hasNext()) {
                val permission = permissionIterator.next()
                val granted = permissionsObject.opt(permission) as? Boolean
                    ?: throw IOException("Baseline grant flag is invalid for " + packageName)
                if (permission.isBlank() || permission.length > 255) {
                    throw IOException("Baseline contains an invalid permission name")
                }
                permissions[permission] = granted
            }
            packages[packageName] = permissions
        }
        return PermissionGrantSnapshot(packages)
    }
}
