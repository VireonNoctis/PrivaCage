package org.privacage.android

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings

/**
 * Reads a small set of Android-exposed privacy settings locally.
 *
 * This intentionally does not read Wi-Fi SSIDs, scan results, location coordinates,
 * installed-app inventories, or send any data off-device.
 */
internal data class DevicePrivacySnapshot(
    val locationServices: String,
    val wifiRadio: String,
    val privateDns: String,
    val activeDefaultNetworkVpn: String,
    val appDeclaredPermissions: List<String>
) {
    fun render(): String = buildString {
        appendLine("Location services: $locationServices")
        appendLine("Wi-Fi radio: $wifiRadio")
        appendLine("Android Private DNS: $privateDns")
        append("Active default network: $activeDefaultNetworkVpn")
        appendLine()
        appendLine()
        append("This is a settings snapshot, not proof that Google, Samsung, Android, or apps are not collecting data. ")
        append("Automatic Private DNS is opportunistic; strict mode depends on the configured provider. ")
        append("A Wi-Fi operator can generally observe connection metadata and destination IPs, but HTTPS protects content in transit. ")
        append("Encrypted DNS hides DNS queries from the local network when correctly active, but the resolver can still see them. ")
        append("A VPN shifts trust to the VPN provider and does not prove that every device connection is tunneled.")
        appendLine()
        appendLine()
        appendLine("PrivaCage's own declared permissions:")
        appDeclaredPermissions.forEach { permission -> appendLine("• " + permission) }
        append("This is the app manifest's permission declaration list, not proof that every permission is actively used. It does not audit Android or manufacturer services.")
    }

    companion object {
        fun capture(context: Context): DevicePrivacySnapshot = DevicePrivacySnapshot(
            locationServices = readLocationState(context),
            wifiRadio = readWifiState(context),
            privateDns = readPrivateDnsState(context),
            activeDefaultNetworkVpn = readVpnState(context),
            appDeclaredPermissions = readOwnDeclaredPermissions(context)
        )

        private fun readOwnDeclaredPermissions(context: Context): List<String> = try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_PERMISSIONS
            )
            packageInfo.requestedPermissions.orEmpty().map { permission ->
                val classification = try {
                    val info = context.packageManager.getPermissionInfo(permission, 0)
                    when (info.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE) {
                        PermissionInfo.PROTECTION_DANGEROUS -> "dangerous/runtime"
                        PermissionInfo.PROTECTION_SIGNATURE -> "signature"
                        PermissionInfo.PROTECTION_NORMAL -> "normal"
                        else -> "other protection level"
                    }
                } catch (exception: PackageManager.NameNotFoundException) {
                    "classification unavailable"
                }
                val purpose = when (permission) {
                    "android.permission.INTERNET" -> "network access for explicitly configured DNS forwarding"
                    "android.permission.ACCESS_WIFI_STATE" -> "read Wi-Fi radio state; this code does not read SSIDs"
                    "android.permission.ACCESS_NETWORK_STATE" -> "read active network/VPN transport state"
                    "android.permission.FOREGROUND_SERVICE" -> "run the user-started DNS filtering service"
                    "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" -> "declare the foreground service type used by this build"
                    else -> "purpose not annotated in the local audit"
                }
                "$permission — $classification; $purpose"
            }.ifEmpty { listOf("No requested permissions found.") }
        } catch (exception: SecurityException) {
            listOf("Permission inventory not readable by this app")
        } catch (exception: PackageManager.NameNotFoundException) {
            listOf("Could not inspect PrivaCage's own package declaration")
        }

        private fun readLocationState(context: Context): String = try {
            val manager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
            val enabled = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                manager.isLocationEnabled
            } else {
                Settings.Secure.getInt(
                    context.contentResolver,
                    Settings.Secure.LOCATION_MODE,
                    Settings.Secure.LOCATION_MODE_OFF
                ) != Settings.Secure.LOCATION_MODE_OFF
            }
            if (enabled) "ON" else "OFF"
        } catch (exception: SecurityException) {
            "Not readable by this app"
        } catch (exception: RuntimeException) {
            "Unavailable (" + exception.javaClass.simpleName + ")"
        }

        private fun readWifiState(context: Context): String = try {
            val manager = context.applicationContext.getSystemService(WifiManager::class.java)
            when {
                manager == null -> "Unavailable"
                manager.isWifiEnabled -> "ON"
                else -> "OFF"
            }
        } catch (exception: SecurityException) {
            "Not readable by this app"
        } catch (exception: RuntimeException) {
            "Unavailable (" + exception.javaClass.simpleName + ")"
        }

        private fun readPrivateDnsState(context: Context): String = try {
            when (Settings.Global.getString(context.contentResolver, "private_dns_mode")?.lowercase()) {
                "off" -> "OFF"
                "opportunistic" -> "Automatic / opportunistic"
                "hostname" -> {
                    val hostname = Settings.Global.getString(context.contentResolver, "private_dns_specifier")
                        ?.takeIf(String::isNotBlank)
                    if (hostname == null) "Strict mode selected; provider hostname unavailable"
                    else "Strict mode: $hostname"
                }
                null, "" -> "Unknown / not exposed by this Android build"
                else -> "Unrecognized mode (not assumed secure)"
            }
        } catch (exception: SecurityException) {
            "Not readable by this app"
        } catch (exception: RuntimeException) {
            "Unavailable (" + exception.javaClass.simpleName + ")"
        }

        private fun readVpnState(context: Context): String = try {
            val manager = context.getSystemService(ConnectivityManager::class.java)
            val active = manager?.activeNetwork
            when {
                manager == null -> "Unavailable"
                active == null -> "No active default network"
                manager.getNetworkCapabilities(active)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true -> "VPN transport detected"
                else -> "No VPN transport detected on the active default network"
            }
        } catch (exception: SecurityException) {
            "Not readable by this app"
        } catch (exception: RuntimeException) {
            "Unavailable (" + exception.javaClass.simpleName + ")"
        }
    }
}
