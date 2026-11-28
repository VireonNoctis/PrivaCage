package org.privacage.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities

/**
 * A privacy-minimal snapshot of Android-visible non-VPN networks.
 *
 * This intentionally omits network IDs, IP addresses, SSIDs, and DNS server addresses. These
 * observations do not establish which underlying network carried a protected resolver socket.
 */
internal object DnsNetworkSnapshot {
    data class Snapshot(val report: String, val fingerprint: String)

    private data class Entry(val transport: String, val status: String, val dnsServerCount: Int) {
        fun fingerprintPart(): String = "$transport|$status|$dnsServerCount"
        fun describe(index: Int): String =
            "Network $index: $transport — $status; DNS servers exposed: $dnsServerCount."
    }

    fun capture(context: Context): Snapshot {
        return try {
            val manager = context.getSystemService(ConnectivityManager::class.java)
                ?: return Snapshot("Android connectivity state is unavailable to this app.", "unavailable")
            val entries = manager.allNetworks.mapNotNull { network: Network ->
                val capabilities = manager.getNetworkCapabilities(network) ?: return@mapNotNull null
                if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
                if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
                val status = when {
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) ->
                        "captive portal detected by Android"
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ->
                        "internet validated by Android at snapshot time"
                    else -> "internet not validated by Android at snapshot time"
                }
                val dnsCount = manager.getLinkProperties(network)?.dnsServers?.size ?: 0
                val transportNames = buildList {
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("Wi-Fi")
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("cellular")
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("Ethernet")
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) add("Bluetooth")
                    if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_USB)) add("USB")
                }
                Entry(
                    transport = transportNames.ifEmpty { listOf("other") }.joinToString(" + "),
                    status = status,
                    dnsServerCount = dnsCount
                )
            }.sortedBy { it.fingerprintPart() }

            if (entries.isEmpty()) {
                Snapshot(
                    report = "No non-VPN network with Android's INTERNET capability is visible to this app.",
                    fingerprint = "no-visible-internet-network"
                )
            } else {
                Snapshot(
                    report = entries.mapIndexed { index, entry -> entry.describe(index + 1) }.joinToString("\n"),
                    fingerprint = entries.joinToString("||") { it.fingerprintPart() }
                )
            }
        } catch (exception: Exception) {
            Snapshot(
                report = "Android network snapshot failed (${exception.javaClass.simpleName}).",
                fingerprint = "snapshot-error-${exception.javaClass.simpleName}"
            )
        }
    }
}
