package org.privacage.android

import android.content.Context
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.OsConstants
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.privacage.audit.AuditExportEvent
import java.io.IOException
import java.net.InetSocketAddress
import java.security.KeyStore
import java.time.Duration
import java.time.Instant
import java.time.format.DateTimeParseException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Optional, bounded, on-device DNS event history.
 *
 * The owner UID is best-effort socket ownership, not guaranteed attribution to the app that
 * originally requested a lookup. Android's system resolver may own the observed socket.
 */
internal object LocalDnsEventHistory {
    const val KEY_ENABLED = "dns_event_history_enabled"
    // Legacy plaintext key: read only during the one-time encrypted migration.
    const val KEY_EVENTS = "dns_event_history_json"
    const val KEY_RETENTION_DAYS = "dns_event_history_retention_days"
    private const val KEY_EVENTS_ENCRYPTED = "dns_event_history_encrypted_v1"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val HISTORY_KEY_ALIAS = "org.privacage.android.dns-history.aes-gcm.v1"
    const val DEFAULT_RETENTION_DAYS = 7
    val RETENTION_OPTIONS_DAYS = listOf(1, 7, 30)

    private const val MAX_EVENTS = 100
    private const val MAX_DOMAIN_LENGTH = 253
    private const val MAX_STORED_HISTORY_BYTES = 256 * 1024

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
        if (serialized.length > MAX_STORED_HISTORY_BYTES) return null
        if (serialized.toByteArray(Charsets.UTF_8).size > MAX_STORED_HISTORY_BYTES) return null
        try {
            StrictJsonKeyScanner.validate(serialized, "Local DNS history")
        } catch (_: IOException) {
            return null
        }
        val events = try {
            JSONArray(serialized)
        } catch (_: JSONException) {
            return null
        }
        val expectedKeys = setOf("timestamp", "domain", "action", "socket_owner")
        for (index in 0 until events.length()) {
            val event = events.optJSONObject(index) ?: return null
            val eventKeys = mutableSetOf<String>()
            val iterator = event.keys()
            while (iterator.hasNext()) eventKeys += iterator.next()
            if (eventKeys != expectedKeys) return null

            val timestamp = event.opt("timestamp") as? String ?: return null
            val domain = event.opt("domain") as? String ?: return null
            val action = event.opt("action") as? String ?: return null
            val socketOwner = event.opt("socket_owner") as? String ?: return null
            if (timestamp.length > 64 || domain.isBlank() || domain.length > MAX_DOMAIN_LENGTH ||
                domain != domain.trim() || domain.any(Char::isISOControl) ||
                action.isBlank() || action.length > 64 || action.any(Char::isISOControl) ||
                socketOwner.isBlank() || socketOwner.length > 512 || socketOwner.any(Char::isISOControl)
            ) return null
            val instant = try {
                Instant.parse(timestamp)
            } catch (_: DateTimeParseException) {
                return null
            }
            if (instant.toString() != timestamp) return null
        }
        return events
    }

    internal fun normalizeRetentionDays(candidate: Int): Int =
        candidate.takeIf { it in RETENTION_OPTIONS_DAYS } ?: DEFAULT_RETENTION_DAYS

    internal fun retentionLabel(days: Int): String = when (normalizeRetentionDays(days)) {
        1 -> "24 hours"
        else -> "${normalizeRetentionDays(days)} days"
    }

    /**
     * Remove expired records without changing the input. If any timestamp is invalid, reject the
     * whole pruning operation so a partial cleanup cannot silently destroy evidence.
     */
    internal fun pruneExpiredEvents(serialized: String?, now: Instant, retentionDays: Int): JSONArray? {
        val events = parseStoredEvents(serialized) ?: return null
        val cutoff = now.minus(Duration.ofDays(normalizeRetentionDays(retentionDays).toLong()))
        val retained = JSONArray()
        for (index in 0 until events.length()) {
            val event = events.optJSONObject(index) ?: return null
            val timestamp = event.opt("timestamp") as? String ?: return null
            val recordedAt = try {
                Instant.parse(timestamp)
            } catch (_: DateTimeParseException) {
                return null
            }
            if (!recordedAt.isBefore(cutoff)) retained.put(event)
        }
        return retained
    }

    fun retentionDays(context: Context): Int {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        val stored = try {
            prefs.getInt(KEY_RETENTION_DAYS, DEFAULT_RETENTION_DAYS)
        } catch (_: ClassCastException) {
            DEFAULT_RETENTION_DAYS
        }
        return normalizeRetentionDays(stored)
    }

    /**
     * Prune on app use rather than running a background service solely to delete local history.
     * Returns false when saved history is invalid; in that case the original value is untouched.
     */
    fun pruneExpired(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        return synchronized(this) { readAndPruneEvents(prefs, Instant.now()) != null }
    }

    private fun readStoredHistory(prefs: SharedPreferences): String {
        if (prefs.contains(KEY_EVENTS_ENCRYPTED)) {
            val envelope = try {
                prefs.getString(KEY_EVENTS_ENCRYPTED, null)
            } catch (exception: ClassCastException) {
                throw IOException("Encrypted DNS history has an invalid stored type; saved data was preserved.", exception)
            } ?: throw IOException("Encrypted DNS history is missing its envelope; saved data was preserved.")

            val key = loadExistingHistoryKey()
                ?: throw IOException(
                    "The Android Keystore key for DNS history is missing. Encrypted data was preserved; " +
                        "PrivaCage will not replace the key or fall back to a plaintext copy."
                )
            val cleartext = LocalDnsHistoryCipher.decrypt(envelope, key)
            if (prefs.contains(KEY_EVENTS) && !prefs.edit().remove(KEY_EVENTS).commit()) {
                throw IOException(
                    "Encrypted DNS history was authenticated, but the legacy plaintext copy could not be removed. " +
                        "Both copies were preserved; refresh to retry the migration."
                )
            }
            return cleartext
        }

        val legacyPlaintext = try {
            prefs.getString(KEY_EVENTS, null)
        } catch (exception: ClassCastException) {
            throw IOException("Legacy DNS history has an invalid stored type; saved data was preserved.", exception)
        } ?: return "[]"

        val key = getOrCreateHistoryKey(prefs)
        val envelope = LocalDnsHistoryCipher.encrypt(legacyPlaintext, key)
        if (!prefs.edit().putString(KEY_EVENTS_ENCRYPTED, envelope).commit()) {
            throw IOException(
                "Could not confirm durable storage of encrypted DNS history. The previous history was preserved."
            )
        }
        if (!prefs.edit().remove(KEY_EVENTS).commit()) {
            throw IOException(
                "The encrypted DNS history was saved, but removal of the old plaintext value could not be confirmed. " +
                    "Existing data was preserved; refresh to retry the migration."
            )
        }
        return legacyPlaintext
    }

    private fun loadExistingHistoryKey(): SecretKey? = try {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            .getKey(HISTORY_KEY_ALIAS, null) as? SecretKey
    } catch (exception: Exception) {
        throw IOException("Android Keystore could not load the DNS-history key; saved data was preserved.", exception)
    }

    private fun getOrCreateHistoryKey(prefs: SharedPreferences): SecretKey {
        val existing = loadExistingHistoryKey()
        if (existing != null) return existing
        if (prefs.contains(KEY_EVENTS_ENCRYPTED)) {
            throw IOException(
                "The key for existing encrypted DNS history is unavailable. The stored ciphertext was preserved."
            )
        }

        return try {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            generator.init(
                KeyGenParameterSpec.Builder(
                    HISTORY_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
            generator.generateKey()
        } catch (exception: Exception) {
            throw IOException("Android Keystore could not create a DNS-history key; stored data was preserved.", exception)
        }
    }

    private fun writeStoredHistory(prefs: SharedPreferences, serialized: String) {
        val key = getOrCreateHistoryKey(prefs)
        val envelope = LocalDnsHistoryCipher.encrypt(serialized, key)
        if (!prefs.edit()
                .putString(KEY_EVENTS_ENCRYPTED, envelope)
                .remove(KEY_EVENTS)
                .commit()
        ) {
            throw IOException("Could not confirm durable storage of encrypted DNS history; existing data was preserved.")
        }
    }

    private fun readAndPruneEvents(prefs: SharedPreferences, now: Instant): JSONArray? {
        val serialized = try {
            readStoredHistory(prefs)
        } catch (_: IOException) {
            return null
        }
        val original = parseStoredEvents(serialized) ?: return null
        val days = try {
            prefs.getInt(KEY_RETENTION_DAYS, DEFAULT_RETENTION_DAYS)
        } catch (_: ClassCastException) {
            DEFAULT_RETENTION_DAYS
        }
        val retained = pruneExpiredEvents(serialized, now, days) ?: return null

        if (retained.length() < original.length()) {
            try {
                writeStoredHistory(prefs, retained.toString())
            } catch (_: IOException) {
                return null
            }
        }
        return retained
    }

    fun record(context: Context, packet: ByteArray, domain: String, action: String): RecordResult {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_ENABLED, false)) return RecordResult.DISABLED
        val normalizedDomain = domain.filterNot(Char::isISOControl).trim()
            .take(MAX_DOMAIN_LENGTH).lowercase()
        val normalizedAction = action.filterNot(Char::isISOControl).trim().take(64)
        if (normalizedDomain.isBlank() || normalizedAction.isBlank()) return RecordResult.HISTORY_UNREADABLE
        val attribution = resolveSocketOwner(context, packet)
            .filterNot(Char::isISOControl).trim().take(512).ifBlank { "Unknown" }
        return synchronized(this) {
            val current = readAndPruneEvents(prefs, Instant.now())
                ?: return RecordResult.HISTORY_UNREADABLE
            val next = JSONArray()
            val start = maxOf(0, current.length() - (MAX_EVENTS - 1))
            for (index in start until current.length()) {
                current.optJSONObject(index)?.let(next::put)
            }
            next.put(JSONObject()
                .put("timestamp", Instant.now().toString())
                .put("domain", normalizedDomain)
                .put("action", normalizedAction)
                .put("socket_owner", attribution))
            try {
                writeStoredHistory(prefs, next.toString())
            } catch (_: IOException) {
                return RecordResult.HISTORY_UNREADABLE
            }
            RecordResult.RECORDED
        }
    }

    fun read(context: Context, limit: Int = 30, catalog: List<TrackerSignature>? = null): List<String> {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        val events = synchronized(this) { readAndPruneEvents(prefs, Instant.now()) }
            ?: return listOf(
                "History is unreadable, oversized, or contains malformed records or timestamps. " +
                    "Saved data was preserved; clear it only to start a fresh local history."
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
        val events = synchronized(this) { readAndPruneEvents(prefs, Instant.now()) }
            ?: throw IOException(
                "Stored DNS history is unreadable, oversized, or contains malformed records or timestamps; " +
                    "export cancelled. Existing saved data was preserved."
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

    fun clear(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PrivacyDnsVpnService.PREFERENCES_NAME, Context.MODE_PRIVATE)
        return synchronized(this) {
            prefs.edit()
                .remove(KEY_EVENTS_ENCRYPTED)
                .remove(KEY_EVENTS)
                .commit()
        }
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
