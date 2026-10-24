package org.privacage.android

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import org.json.JSONArray
import org.json.JSONObject
import org.privacage.audit.AuditExportEvent
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.time.Instant

/**
 * Optional, bounded, on-device DNS event history.
 *
 * The owner UID is best-effort socket ownership, not guaranteed attribution to the app that
 * originally requested a lookup. Android's system resolver may own the observed socket.
 */
internal object LocalDnsEventHistory {
    const val KEY_ENABLED = "dns_event_history_enabled"
    const val KEY_EVENTS = "dns_event_history_json"
    private const val MAX_EVENTS = 100
    private const val MAX_DOMAIN_LENGTH = 253

    fun record(context: Context, packet: ByteArray, domain: String, action: String) {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_ENABLED, false)) return
        val normalizedDomain = domain.take(MAX_DOMAIN_LENGTH).lowercase()
        val attribution = resolveSocketOwner(context, packet)
        synchronized(this) {
            val current = try {
                JSONArray(prefs.getString(KEY_EVENTS, "[]").orEmpty())
            } catch (_: Exception) {
                JSONArray()
            }
            val next = JSONArray()
            val start = maxOf(0, current.length() - (MAX_EVENTS - 1))
            for (index in start until current.length()) {
                current.optJSONObject(index)?.let(next::put)
            }
            next.put(JSONObject()
                .put("timestamp", Instant.now().toString())
                .put("domain", normalizedDomain)
                .put("action", action)
                .put("socket_owner", attribution))
            prefs.edit().putString(KEY_EVENTS, next.toString()).apply()
        }
    }

    fun read(context: Context, limit: Int = 30): List<String> {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        val events = try {
            JSONArray(prefs.getString(KEY_EVENTS, "[]").orEmpty())
        } catch (_: Exception) {
            return listOf("History is unreadable; clear it to start a fresh local history.")
        }
        val result = mutableListOf<String>()
        val start = maxOf(0, events.length() - limit.coerceIn(1, MAX_EVENTS))
        for (index in events.length() - 1 downTo start) {
            val event = events.optJSONObject(index) ?: continue
            result += "${event.optString("timestamp")}  [${event.optString("action")}] ${event.optString("domain")}\nSocket owner: ${event.optString("socket_owner", "Unknown")}"
        }
        return result
    }

    fun readForExport(context: Context): List<AuditExportEvent> {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        val events = try {
            JSONArray(prefs.getString(KEY_EVENTS, "[]").orEmpty())
        } catch (exception: Exception) {
            throw IOException("Stored DNS history is unreadable; export cancelled instead of silently omitting events.", exception)
        }
        val result = ArrayList<AuditExportEvent>(events.length())
        for (index in 0 until events.length()) {
            val event = events.optJSONObject(index)
                ?: throw IOException("Stored DNS history contains a malformed record at index $index; export cancelled.")
            result += AuditExportEvent(
                timestamp = event.optString("timestamp", ""),
                category = event.optString("action", ""),
                hostname = event.optString("domain", ""),
                socketOwnerLabel = event.optString("socket_owner", "Unknown")
            )
        }
        return result
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
            .edit().remove(KEY_EVENTS).apply()
    }

    private fun resolveSocketOwner(context: Context, packet: ByteArray): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return "Unavailable on this Android version; initiating app unknown"
        }
        if (packet.size < 28 || (packet[0].toInt() and 0x0f) < 5 || (packet[9].toInt() and 0xff) != OsConstants.IPPROTO_UDP) {
            return "Unavailable for this packet; initiating app unknown"
        }
        val headerLength = (packet[0].toInt() and 0x0f) * 4
        if (packet.size < headerLength + 8) return "Unavailable for malformed packet"
        return try {
            val localAddress = InetAddress.getByAddress(packet.copyOfRange(12, 16))
            val remoteAddress = InetAddress.getByAddress(packet.copyOfRange(16, 20))
            val localPort = unsignedShort(packet, headerLength)
            val remotePort = unsignedShort(packet, headerLength + 2)
            val uid = context.getSystemService(ConnectivityManager::class.java)
                .getConnectionOwnerUid(
                    OsConstants.IPPROTO_UDP,
                    InetSocketAddress(localAddress, localPort),
                    InetSocketAddress(remoteAddress, remotePort)
                )
            if (uid < 0) return "No socket owner reported; initiating app unknown"
            if (uid == Process.SYSTEM_UID) return "Android system resolver (initiating app not identifiable)"
            val packages = context.packageManager.getPackagesForUid(uid).orEmpty()
            if (packages.isEmpty()) return "UID $uid (package not exposed)"
            val labels = packages.take(3).map { packageName ->
                try {
                    val info = context.packageManager.getApplicationInfo(packageName, 0)
                    context.packageManager.getApplicationLabel(info).toString()
                } catch (_: Exception) {
                    packageName
                }
            }
            "UID $uid: " + labels.joinToString(", ")
        } catch (_: Exception) {
            "Socket-owner lookup unavailable; initiating app unknown"
        }
    }

    private fun unsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
}
