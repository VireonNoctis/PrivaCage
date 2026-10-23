package org.privacage.android

import android.content.Context
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
    val activeDefaultNetworkVpn: String
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
    }

    companion object {
        fun capture(context: Context): DevicePrivacySnapshot = DevicePrivacySnapshot(
            locationServices = readLocationState(context),
            wifiRadio = readWifiState(context),
            privateDns = readPrivateDnsState(context),
            activeDefaultNetworkVpn = readVpnState(context)
        )

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
