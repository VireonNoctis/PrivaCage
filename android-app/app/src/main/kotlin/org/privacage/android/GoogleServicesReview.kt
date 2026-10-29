package org.privacage.android

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

internal data class GoogleServiceTarget(
    val packageName: String,
    val displayName: String,
    val purpose: String
)

internal enum class GoogleServiceStatus(val label: String) {
    ENABLED("Installed and enabled"),
    DISABLED("Installed but disabled"),
    NOT_INSTALLED_OR_NOT_VISIBLE("Not installed or not visible to this profile"),
    INSPECTION_UNAVAILABLE("Inspection unavailable")
}

internal data class GoogleServiceObservation(
    val target: GoogleServiceTarget,
    val status: GoogleServiceStatus,
    val versionName: String? = null,
    val systemPackage: Boolean? = null,
    val diagnostic: String? = null
)

internal object GoogleServicesReview {
    const val PLAY_SERVICES_PACKAGE = "com.google.android.gms"
    const val SERVICES_FRAMEWORK_PACKAGE = "com.google.android.gsf"
    const val PLAY_STORE_PACKAGE = "com.android.vending"

    val targets = listOf(
        GoogleServiceTarget(
            packageName = PLAY_SERVICES_PACKAGE,
            displayName = "Google Play services",
            purpose = "Shared Google APIs used by some installed apps; package presence does not establish what data is sent."
        ),
        GoogleServiceTarget(
            packageName = SERVICES_FRAMEWORK_PACKAGE,
            displayName = "Google Services Framework",
            purpose = "Google device/service framework component; app and OS dependencies vary by device."
        ),
        GoogleServiceTarget(
            packageName = PLAY_STORE_PACKAGE,
            displayName = "Google Play Store",
            purpose = "App store, delivery, and update component; some app workflows depend on it."
        )
    )

    fun inspect(packageManager: PackageManager): List<GoogleServiceObservation> =
        targets.map { target -> inspectPackage(packageManager, target) }

    fun inspectPackage(
        packageManager: PackageManager,
        target: GoogleServiceTarget
    ): GoogleServiceObservation {
        return try {
            val appInfo = packageManager.getApplicationInfo(target.packageName, 0)
            val packageInfo = packageManager.getPackageInfo(target.packageName, 0)
            val systemFlags = ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
            GoogleServiceObservation(
                target = target,
                status = if (appInfo.enabled) GoogleServiceStatus.ENABLED else GoogleServiceStatus.DISABLED,
                versionName = packageInfo.versionName,
                systemPackage = (appInfo.flags and systemFlags) != 0
            )
        } catch (exception: PackageManager.NameNotFoundException) {
            GoogleServiceObservation(
                target = target,
                status = GoogleServiceStatus.NOT_INSTALLED_OR_NOT_VISIBLE,
                diagnostic = "Android did not expose a package matching this ID; it may be absent from this user/profile."
            )
        } catch (exception: SecurityException) {
            GoogleServiceObservation(
                target = target,
                status = GoogleServiceStatus.INSPECTION_UNAVAILABLE,
                diagnostic = "Android denied package inspection (SecurityException)."
            )
        } catch (exception: RuntimeException) {
            GoogleServiceObservation(
                target = target,
                status = GoogleServiceStatus.INSPECTION_UNAVAILABLE,
                diagnostic = "Package inspection failed (${exception.javaClass.simpleName})."
            )
        }
    }

    fun render(observations: List<GoogleServiceObservation>): String = buildString {
        appendLine("GOOGLE SERVICES — LOCAL PACKAGE REVIEW")
        appendLine("Read-only; no package settings are changed and no results are uploaded.")
        appendLine("")

        if (observations.isEmpty()) {
            appendLine("No package results were returned.")
        }

        observations.forEach { observation ->
            appendLine("${observation.target.displayName} (${observation.target.packageName})")
            appendLine("  State: ${observation.status.label}")
            observation.versionName?.takeIf(String::isNotBlank)?.let {
                appendLine("  Version: $it")
            }
            observation.systemPackage?.let {
                appendLine("  System package: ${if (it) "yes" else "no"}")
            }
            appendLine("  Context: ${observation.target.purpose}")
            observation.diagnostic?.let { appendLine("  Detail: $it") }
            appendLine("")
        }

        append("This does not inspect network connections or prove whether data was collected. ")
        append("PrivaCage does not disable these packages. Android may not offer a Disable control for core system components; ")
        append("changing them can affect push, location, sign-in, store updates/purchases, or app integrity depending on the device and apps.")
    }
}
