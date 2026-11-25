package org.privacage.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.time.format.DateTimeParseException
import java.util.UUID

internal data class DevicePrivacyTimelineEntry(
    val id: String,
    val observedAt: Instant,
    val snapshot: DevicePrivacySnapshot
)

/**
 * Explicitly user-saved observations of a small set of OS-exposed settings.
 *
 * This is not a background event feed. Timestamps record when the user saved a
 * snapshot, not when a setting changed or who changed it.
 */
internal object DevicePrivacyTimelineStore {
    const val MAX_RECORDS = 30
    const val MAX_PLAINTEXT_BYTES = 256 * 1024

    private const val PREFERENCES_NAME = "privacage_device_privacy_timeline"
    private const val ENCRYPTED_KEY = "device_privacy_timeline_encrypted_v1"
    private const val KEY_ALIAS = "org.privacage.device-privacy-timeline.v1"
    private const val AAD_LABEL = "device-privacy-timeline"
    private const val SCHEMA_VERSION = 1
    private const val MAX_FIELD_CHARS = 512
    private const val MAX_PERMISSION_COUNT = 64
    private const val MAX_PERMISSION_TOTAL_CHARS = 16 * 1024
    private const val DISPLAY_RECORDS = 10

    private val rootFields = setOf("schema_version", "entries")
    private val entryFields = setOf(
        "id",
        "observed_at",
        "location_services",
        "wifi_radio",
        "private_dns",
        "active_default_network_vpn",
        "app_declared_permissions"
    )
    private const val EMPTY_JSON = """{"schema_version":1,"entries":[]}"""

    fun read(context: Context): List<DevicePrivacyTimelineEntry> {
        val encoded = AndroidSensitivePreferenceVault.read(
            context = context.applicationContext,
            preferencesName = PREFERENCES_NAME,
            encryptedKey = ENCRYPTED_KEY,
            keyAlias = KEY_ALIAS,
            aadLabel = AAD_LABEL,
            defaultValue = EMPTY_JSON,
            maximumPlaintextBytes = MAX_PLAINTEXT_BYTES,
            validateValue = { decodeRecords(it) }
        ) ?: EMPTY_JSON
        return decodeRecords(encoded)
    }

    fun save(
        context: Context,
        snapshot: DevicePrivacySnapshot,
        observedAt: Instant = Instant.now()
    ): List<DevicePrivacyTimelineEntry> {
        val updated = appendRecord(read(context), snapshot, observedAt)
        val encoded = encodeRecords(updated)
        AndroidSensitivePreferenceVault.write(
            context = context.applicationContext,
            preferencesName = PREFERENCES_NAME,
            encryptedKey = ENCRYPTED_KEY,
            keyAlias = KEY_ALIAS,
            aadLabel = AAD_LABEL,
            plaintext = encoded,
            maximumPlaintextBytes = MAX_PLAINTEXT_BYTES,
            validateValue = { decodeRecords(it) }
        )
        return updated
    }

    fun clear(context: Context): Boolean =
        AndroidSensitivePreferenceVault.clear(
            context = context.applicationContext,
            preferencesName = PREFERENCES_NAME,
            encryptedKey = ENCRYPTED_KEY
        )

    internal fun appendRecord(
        existing: List<DevicePrivacyTimelineEntry>,
        snapshot: DevicePrivacySnapshot,
        observedAt: Instant
    ): List<DevicePrivacyTimelineEntry> {
        val validated = decodeRecords(encodeRecords(existing))
        val entry = DevicePrivacyTimelineEntry(
            id = UUID.randomUUID().toString(),
            observedAt = observedAt,
            snapshot = snapshot
        )
        val updated = (validated + entry).takeLast(MAX_RECORDS)
        encodeRecords(updated)
        return updated
    }

    internal fun encodeRecords(records: List<DevicePrivacyTimelineEntry>): String {
        require(records.size <= MAX_RECORDS) {
            "Device privacy history exceeds the 30-observation limit."
        }
        val encodedEntries = JSONArray()
        records.forEach { entry ->
            val permissions = JSONArray()
            entry.snapshot.appDeclaredPermissions.forEach(permissions::put)
            encodedEntries.put(
                JSONObject()
                    .put("id", entry.id)
                    .put("observed_at", entry.observedAt.toString())
                    .put("location_services", entry.snapshot.locationServices)
                    .put("wifi_radio", entry.snapshot.wifiRadio)
                    .put("private_dns", entry.snapshot.privateDns)
                    .put("active_default_network_vpn", entry.snapshot.activeDefaultNetworkVpn)
                    .put("app_declared_permissions", permissions)
            )
        }
        val encoded = JSONObject()
            .put("schema_version", SCHEMA_VERSION)
            .put("entries", encodedEntries)
            .toString()
        require(encoded.toByteArray(Charsets.UTF_8).size <= MAX_PLAINTEXT_BYTES) {
            "Device privacy history exceeds its encrypted storage limit."
        }
        decodeRecords(encoded)
        return encoded
    }

    internal fun decodeRecords(encoded: String): List<DevicePrivacyTimelineEntry> {
        val bytes = encoded.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty() || bytes.size > MAX_PLAINTEXT_BYTES) {
            throw IllegalStateException("Device privacy history is empty or exceeds its size limit.")
        }
        bytes.fill(0)
        try {
            StrictJsonKeyScanner.validate(encoded, "Device privacy snapshot history")
        } catch (exception: Exception) {
            throw IllegalStateException("Device privacy history is malformed or contains duplicate keys.", exception)
        }
        val root = try {
            JSONObject(encoded)
        } catch (exception: Exception) {
            throw IllegalStateException("Device privacy history is not valid JSON.", exception)
        }
        if (root.keys().asSequence().toSet() != rootFields ||
            root.opt("schema_version") !is Int ||
            root.optInt("schema_version") != SCHEMA_VERSION
        ) {
            throw IllegalStateException("Device privacy history has unsupported fields or schema.")
        }
        val array = root.optJSONArray("entries")
            ?: throw IllegalStateException("Device privacy history entries must be an array.")
        if (array.length() > MAX_RECORDS) {
            throw IllegalStateException("Device privacy history exceeds the 30-observation limit.")
        }

        val seenIds = mutableSetOf<String>()
        val decoded = ArrayList<DevicePrivacyTimelineEntry>(array.length())
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index)
                ?: throw IllegalStateException("Device privacy history entry is not an object.")
            if (item.keys().asSequence().toSet() != entryFields) {
                throw IllegalStateException("Device privacy history entry has missing or unknown fields.")
            }
            val id = requiredString(item, "id")
            val canonicalId = try {
                UUID.fromString(id).toString()
            } catch (exception: IllegalArgumentException) {
                throw IllegalStateException("Device privacy history entry ID is invalid.", exception)
            }
            if (canonicalId != id || !seenIds.add(id)) {
                throw IllegalStateException("Device privacy history contains a non-canonical or duplicate ID.")
            }
            val observedAtText = requiredString(item, "observed_at")
            val observedAt = try {
                Instant.parse(observedAtText)
            } catch (exception: DateTimeParseException) {
                throw IllegalStateException("Device privacy history timestamp is invalid.", exception)
            }
            if (observedAt.toString() != observedAtText) {
                throw IllegalStateException("Device privacy history timestamp is not canonical UTC.")
            }

            val permissionArray = item.optJSONArray("app_declared_permissions")
                ?: throw IllegalStateException("Device privacy permission declarations must be an array.")
            if (permissionArray.length() > MAX_PERMISSION_COUNT) {
                throw IllegalStateException("Device privacy permission declarations exceed the 64-entry limit.")
            }
            val permissions = ArrayList<String>(permissionArray.length())
            val seenPermissions = mutableSetOf<String>()
            var totalPermissionChars = 0
            for (permissionIndex in 0 until permissionArray.length()) {
                val permission = permissionArray.opt(permissionIndex) as? String
                    ?: throw IllegalStateException("Device privacy permission declaration must be a string.")
                validateText(permission, "permission declaration")
                totalPermissionChars += permission.length
                if (totalPermissionChars > MAX_PERMISSION_TOTAL_CHARS || !seenPermissions.add(permission)) {
                    throw IllegalStateException("Device privacy permission declarations are duplicated or too large.")
                }
                permissions += permission
            }

            decoded += DevicePrivacyTimelineEntry(
                id = id,
                observedAt = observedAt,
                snapshot = DevicePrivacySnapshot(
                    locationServices = requiredString(item, "location_services"),
                    wifiRadio = requiredString(item, "wifi_radio"),
                    privateDns = requiredString(item, "private_dns"),
                    activeDefaultNetworkVpn = requiredString(item, "active_default_network_vpn"),
                    appDeclaredPermissions = permissions
                )
            )
        }
        return decoded
    }

    internal fun changesBetween(
        previous: DevicePrivacySnapshot,
        current: DevicePrivacySnapshot
    ): List<String> = buildList {
        if (previous.locationServices != current.locationServices) {
            add("Location services: ${previous.locationServices} → ${current.locationServices}")
        }
        if (previous.wifiRadio != current.wifiRadio) {
            add("Wi-Fi radio: ${previous.wifiRadio} → ${current.wifiRadio}")
        }
        if (previous.privateDns != current.privateDns) {
            add("Android Private DNS: ${previous.privateDns} → ${current.privateDns}")
        }
        if (previous.activeDefaultNetworkVpn != current.activeDefaultNetworkVpn) {
            add("Default-network VPN: ${previous.activeDefaultNetworkVpn} → ${current.activeDefaultNetworkVpn}")
        }
        if (previous.appDeclaredPermissions.toSet() != current.appDeclaredPermissions.toSet()) {
            add("PrivaCage's own declared-permission inventory changed.")
        }
    }

    internal fun renderHistory(records: List<DevicePrivacyTimelineEntry>): String {
        val validated = decodeRecords(encodeRecords(records))
        if (validated.isEmpty()) {
            return "No snapshots have been saved. Refreshing the current snapshot does not create a history entry."
        }
        val firstDisplayedIndex = maxOf(0, validated.size - DISPLAY_RECORDS)
        return buildString {
            append("Showing the newest ")
            append(validated.size - firstDisplayedIndex)
            append(" of ")
            append(validated.size)
            appendLine(" user-saved observations.")
            appendLine()
            for (index in validated.indices.reversed().take(DISPLAY_RECORDS)) {
                val entry = validated[index]
                append("Observed at (device clock): ")
                appendLine(entry.observedAt.toString())
                append("Location services: ")
                appendLine(entry.snapshot.locationServices)
                append("Wi-Fi radio: ")
                appendLine(entry.snapshot.wifiRadio)
                append("Android Private DNS: ")
                appendLine(entry.snapshot.privateDns)
                append("Active default network VPN: ")
                appendLine(entry.snapshot.activeDefaultNetworkVpn)
                append("PrivaCage declared permissions: ")
                appendLine(entry.snapshot.appDeclaredPermissions.size.toString())
                if (index > 0) {
                    val changes = changesBetween(validated[index - 1].snapshot, entry.snapshot)
                    appendLine("Differences from the previous saved observation:")
                    if (changes.isEmpty()) appendLine("• No difference in the exposed fields.")
                    else changes.forEach { append("• ").appendLine(it) }
                } else {
                    appendLine("First saved observation; no earlier local comparison exists.")
                }
                appendLine()
            }
            append("This is a user-saved comparison of exposed settings, not a background event feed. ")
            append("It cannot establish when a setting changed, who changed it, or the state of settings Android does not expose.")
        }
    }

    private fun requiredString(value: JSONObject, key: String): String {
        val text = value.opt(key) as? String
            ?: throw IllegalStateException("Device privacy history field " + key + " must be a string.")
        validateText(text, key)
        return text
    }

    private fun validateText(value: String, label: String) {
        if (value.isBlank() || value.length > MAX_FIELD_CHARS ||
            value.any { it.code < 0x20 || it.code == 0x7f }
        ) {
            throw IllegalStateException("Device privacy history " + label + " is blank, too long, or contains control characters.")
        }
    }
}
