package org.privacage.android

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import java.time.Instant

internal enum class MonitoringObservationStatus { AVAILABLE, PARTIAL, UNAVAILABLE }

internal data class MonitoringAccessComponent(val packageName: String, val className: String)

internal data class MonitoringComponentObservation(
    val status: MonitoringObservationStatus,
    val components: List<MonitoringAccessComponent>,
    val source: String,
    val detail: String? = null
)

internal data class MonitoringVpnObservation(
    val usesVpnTransportOnDefaultNetwork: Boolean?,
    val source: String,
    val detail: String? = null
)

internal data class MonitoringAccessSnapshot(
    val capturedAt: Instant,
    val accessibilityServices: MonitoringComponentObservation,
    val activeDeviceAdministrators: MonitoringComponentObservation,
    val notificationListeners: MonitoringComponentObservation,
    val defaultNetworkVpn: MonitoringVpnObservation
)

internal data class ParsedMonitoringComponentSetting(
    val components: List<MonitoringAccessComponent>,
    val invalidEntryCount: Int,
    val truncated: Boolean,
    val inputTooLarge: Boolean
) {
    val isComplete: Boolean
        get() = invalidEntryCount == 0 && !truncated && !inputTooLarge
}

/**
 * Reads only public Android state exposed to an ordinary app. Results are returned in memory;
 * this object does not persist, upload, notify, disable, or otherwise modify anything.
 */
internal object MonitoringAccessAudit {
    const val MAX_SETTING_CHARS = 16 * 1024
    const val MAX_COMPONENTS = 100
    private const val MAX_COMPONENT_NAME_CHARS = 512
    private const val ENABLED_NOTIFICATION_LISTENERS_SETTING = "enabled_notification_listeners"

    fun collect(context: Context, capturedAt: Instant = Instant.now()): MonitoringAccessSnapshot =
        MonitoringAccessSnapshot(
            capturedAt = capturedAt,
            accessibilityServices = readAccessibilityServices(context),
            activeDeviceAdministrators = readActiveDeviceAdministrators(context),
            notificationListeners = readNotificationListeners(context),
            defaultNetworkVpn = readDefaultNetworkVpn(context)
        )

    internal fun parseEnabledComponentSetting(raw: String?): ParsedMonitoringComponentSetting {
        if (raw == null || raw.isEmpty()) {
            return ParsedMonitoringComponentSetting(emptyList(), 0, false, false)
        }
        if (raw.length > MAX_SETTING_CHARS) {
            return ParsedMonitoringComponentSetting(emptyList(), 0, false, true)
        }

        val entries = raw.split(':')
        val components = LinkedHashMap<String, MonitoringAccessComponent>()
        var invalid = 0
        entries.take(MAX_COMPONENTS).forEach { entry ->
            val component = parseFlattenedComponent(entry)
            if (component == null) {
                invalid += 1
            } else {
                components.putIfAbsent(
                    component.packageName + "/" + component.className,
                    component
                )
            }
        }
        return ParsedMonitoringComponentSetting(
            components = components.values.toList(),
            invalidEntryCount = invalid,
            truncated = entries.size > MAX_COMPONENTS,
            inputTooLarge = false
        )
    }

    private fun readAccessibilityServices(context: Context): MonitoringComponentObservation {
        val source = "AccessibilityManager.getEnabledAccessibilityServiceList(FEEDBACK_ALL_MASK)"
        val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return unavailable(source, "Android did not provide the accessibility service manager.")
        return try {
            val services = manager.getEnabledAccessibilityServiceList(
                AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            ) ?: return unavailable(source, "Android did not return an accessibility-service list.")
            val components = ArrayList<MonitoringAccessComponent>()
            var invalid = 0
            services.take(MAX_COMPONENTS).forEach { service ->
                val serviceInfo = service.resolveInfo?.serviceInfo
                val component = serviceInfo?.let { normalizeComponent(it.packageName, it.name) }
                if (component == null) invalid += 1 else components += component
            }
            observation(
                source,
                components.distinctBy { it.packageName + "/" + it.className },
                invalid,
                services.size > MAX_COMPONENTS
            )
        } catch (exception: SecurityException) {
            unavailable(source, "Android denied access to this setting.")
        }
    }

    private fun readActiveDeviceAdministrators(context: Context): MonitoringComponentObservation {
        val source = "DevicePolicyManager.getActiveAdmins()"
        val manager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            ?: return unavailable(source, "Android did not provide the device-policy manager.")
        return try {
            val admins = manager.activeAdmins.orEmpty()
            val components = ArrayList<MonitoringAccessComponent>()
            var invalid = 0
            admins.take(MAX_COMPONENTS).forEach { admin ->
                val component = normalizeComponent(admin.packageName, admin.className)
                if (component == null) invalid += 1 else components += component
            }
            observation(
                source,
                components.distinctBy { it.packageName + "/" + it.className },
                invalid,
                admins.size > MAX_COMPONENTS
            )
        } catch (exception: SecurityException) {
            unavailable(source, "Android denied access to this setting.")
        }
    }

    private fun readNotificationListeners(context: Context): MonitoringComponentObservation {
        val source = "Settings.Secure.enabled_notification_listeners"
        return try {
            notificationListenerObservation(
                Settings.Secure.getString(
                    context.contentResolver,
                    ENABLED_NOTIFICATION_LISTENERS_SETTING
                )
            )
        } catch (exception: SecurityException) {
            unavailable(source, "Android denied access to this setting.")
        }
    }

    internal fun notificationListenerObservation(raw: String?): MonitoringComponentObservation {
        val source = "Settings.Secure.enabled_notification_listeners"
        if (raw == null) {
            return unavailable(
                source,
                "Android returned no stored value. An unset value cannot distinguish no enabled listeners from an unavailable or OEM-restricted setting."
            )
        }

        val parsed = parseEnabledComponentSetting(raw)
        val detail = when {
            parsed.inputTooLarge ->
                "The setting exceeded the local input limit; no partial list is shown."
            parsed.truncated ->
                "The setting contains more than " + MAX_COMPONENTS + " entries; the displayed list is incomplete."
            parsed.invalidEntryCount > 0 ->
                parsed.invalidEntryCount.toString() + " malformed setting entries were omitted."
            else -> null
        }
        return MonitoringComponentObservation(
            status = if (parsed.isComplete) MonitoringObservationStatus.AVAILABLE
                else MonitoringObservationStatus.PARTIAL,
            components = parsed.components,
            source = source,
            detail = detail
        )
    }

    private fun readDefaultNetworkVpn(context: Context): MonitoringVpnObservation {
        val source = "ConnectivityManager.getActiveNetwork()/getNetworkCapabilities()"
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return MonitoringVpnObservation(null, source, "Android did not provide connectivity state.")
        return try {
            val network = manager.activeNetwork
                ?: return MonitoringVpnObservation(null, source, "No active default network was returned; VPN status is unknown.")
            val capabilities = manager.getNetworkCapabilities(network)
                ?: return MonitoringVpnObservation(null, source, "Android did not return capabilities for the active default network.")
            MonitoringVpnObservation(
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                source
            )
        } catch (exception: SecurityException) {
            MonitoringVpnObservation(null, source, "Android denied access to network state.")
        }
    }

    private fun observation(
        source: String,
        components: List<MonitoringAccessComponent>,
        invalidEntryCount: Int,
        truncated: Boolean
    ): MonitoringComponentObservation {
        val details = ArrayList<String>()
        if (invalidEntryCount > 0) details += invalidEntryCount.toString() + " component records could not be read."
        if (truncated) details += "More than " + MAX_COMPONENTS + " components were reported; the displayed list is incomplete."
        val detail = details.takeIf { it.isNotEmpty() }?.joinToString(" ")
        return MonitoringComponentObservation(
            if (detail == null) MonitoringObservationStatus.AVAILABLE else MonitoringObservationStatus.PARTIAL,
            components,
            source,
            detail
        )
    }

    private fun unavailable(source: String, detail: String) =
        MonitoringComponentObservation(MonitoringObservationStatus.UNAVAILABLE, emptyList(), source, detail)

    private fun parseFlattenedComponent(raw: String): MonitoringAccessComponent? {
        val value = raw.trim()
        if (value.isEmpty() || value.length > MAX_COMPONENT_NAME_CHARS) return null
        val separator = value.indexOf('/')
        if (separator <= 0 || separator == value.lastIndex || value.indexOf('/', separator + 1) >= 0) return null
        return normalizeComponent(value.substring(0, separator), value.substring(separator + 1))
    }

    private fun normalizeComponent(packageName: String, className: String): MonitoringAccessComponent? {
        if (!isQualifiedName(packageName) || className.isBlank() || className.length > MAX_COMPONENT_NAME_CHARS) return null
        val normalizedClass = when {
            className.startsWith(".") -> packageName + className
            className.contains(".") -> className
            else -> packageName + "." + className
        }
        if (!isQualifiedName(normalizedClass)) return null
        return MonitoringAccessComponent(packageName, normalizedClass)
    }

    private fun isQualifiedName(value: String): Boolean {
        if (value.isEmpty() || value.length > MAX_COMPONENT_NAME_CHARS) return false
        return value.split('.').all { segment ->
            segment.isNotEmpty() &&
                (segment[0].isLetter() || segment[0] == '_' || segment[0] == '$') &&
                segment.drop(1).all { it.isLetterOrDigit() || it == '_' || it == '$' }
        }
    }
}
