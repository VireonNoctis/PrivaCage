package org.privacage.android

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo

/**
 * Local audit of dangerous permissions declared by launcher-visible applications.
 *
 * Android package visibility intentionally limits this to apps discoverable through
 * the launcher intent. It does not claim to inventory headless/system/OEM services.
 */
internal object AppPermissionAudit {
    private const val MAX_APPS_IN_REPORT = 60

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
            val requested = packageInfo.requestedPermissions ?: continue
            val flags = packageInfo.requestedPermissionsFlags
            val sensitive = requested.mapIndexedNotNull { index, permission ->
                val isDangerous = try {
                    val info = packageManager.getPermissionInfo(permission, 0)
                    (info.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE) ==
                        PermissionInfo.PROTECTION_DANGEROUS
                } catch (exception: PackageManager.NameNotFoundException) {
                    false
                } catch (exception: SecurityException) {
                    false
                }
                if (!isDangerous) return@mapIndexedNotNull null

                val granted = flags?.getOrNull(index)
                    ?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) == PackageInfo.REQUESTED_PERMISSION_GRANTED
                permission.substringAfterLast('.') +
                    if (granted) " — GRANTED" else " — NOT CURRENTLY GRANTED"
            }.sorted()

            if (sensitive.isNotEmpty()) {
                val label = try {
                    packageInfo.applicationInfo?.let { packageManager.getApplicationLabel(it).toString() } ?: packageName
                } catch (exception: RuntimeException) {
                    packageName
                }
                rows += label + " (" + packageName + ")\n" + sensitive.joinToString("\n") { "  • " + it }
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

        output.append("\n\nImportant limits: this reads manifest declarations and current grant flags, not live sensor use or data transmission. ")
            .append("Apps without launcher activities, many headless system components, privileged Google/Samsung services, work-profile apps, and hidden packages may be absent. ")
            .append("A granted permission does not prove it was used; a missing permission does not prove an app collects no data. ")
            .append("Use Android Settings to change permissions; PrivaCage does not silently revoke them.")
        return output.toString()
    }
}
