package org.privacage.android

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.privacage.audit.AuditExportEvent
import java.io.IOException
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
    private const val MAX_STORED_HISTORY_CHARS = 256 * 1024

    enum class RecordResult {
        DISABLED,
        RECORDED,
        HISTORY_UNREADABLE
    }

    /**
     * Parse history without silently dropping malformed records. A null result means that saved
     * evidence must be preserved for the user to inspect or explicitly clear.
     */
    internal fun parseStoredEvents(serialized: String?): JSONArray? {
        if (serialized == null) return JSONArray()
        if (serialized.length > MAX_STORED_HISTORY_CHARS) return null
        val events = try {
            JSONArray(serialized)
        } catch (_: JSONException) {
            return null
        }
        for (index in 0 until events.length()) {
            if (events.optJSONObject(index) == null) return null
        }
        return events
    }

    fun record(context: Context, packet: ByteArray, domain: String, action: String): RecordResult {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_ENABLED, false)) return RecordResult.DISABLED
        val normalizedDomain = domain.take(MAX_DOMAIN_LENGTH).lowercase()
        val attribution = resolveSocketOwner(context, packet)
        return synchronized(this) {
            val current = parseStoredEvents(prefs.getString(KEY_EVENTS, "[]"))
                ?: return RecordResult.HISTORY_UNREADABLE
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
            RecordResult.RECORDED
        }
    }

    fun read(context: Context, limit: Int = 30, catalog: List<TrackerSignature>? = null): List<String> {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        val events = parseStoredEvents(prefs.getString(KEY_EVENTS, "[]"))
            ?: return listOf(
                "History is unreadable, oversized, or contains malformed records. Saved data was preserved; " +
                    "clear it only to start a fresh local history."
            )
        val result = mutableListOf<String>()
        val start = maxOf(0, events.length() - limit.coerceIn(1, MAX_EVENTS))
        for (index in events.length() - 1 downTo start) {
            val event = events.optJSONObject(index) ?: continue
            val hostname = event.optString("domain")
            val classification = DnsHistoryDomainClassifier.classify(hostname, catalog)
            result += "${event.optString("timestamp")}  [${event.optString("action")}] $hostname\nSocket owner: ${event.optString("socket_owner", "Unknown")}\n${classification.summary()}"
        }
        return result
    }

    fun readForExport(context: Context): List<AuditExportEvent> {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        val events = parseStoredEvents(prefs.getString(KEY_EVENTS, "[]"))
            ?: throw IOException(
                "Stored DNS history is unreadable, oversized, or contains malformed records; export cancelled. " +
                    "Existing saved data was preserved."
            )
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
        val tuple = DnsUdpSocketTupleParser.parse(packet)
            ?: return "Unavailable for this IPv4/IPv6 UDP DNS packet; initiating app unknown"
        return try {
            val uid = context.getSystemService(ConnectivityManager::class.java)
                .getConnectionOwnerUid(
                    OsConstants.IPPROTO_UDP,
                    InetSocketAddress(tuple.sourceAddress, tuple.sourcePort),
                    InetSocketAddress(tuple.destinationAddress, tuple.destinationPort)
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
}
