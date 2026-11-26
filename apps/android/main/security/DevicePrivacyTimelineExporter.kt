package org.privacage.android

import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.time.Instant

internal data class DevicePrivacyTimelineExportResult(
    val json: String,
    val previewText: String,
    val recordCount: Int
)

/** A redaction-first export of user-saved observations; deliberately unsigned and unencrypted. */
internal object DevicePrivacyTimelineExporter {
    const val MAX_EXPORT_BYTES = 512 * 1024

    fun prepare(
        records: List<DevicePrivacyTimelineEntry>,
        generatedAt: Instant = Instant.now()
    ): DevicePrivacyTimelineExportResult {
        val validated = DevicePrivacyTimelineStore.decodeRecords(
            DevicePrivacyTimelineStore.encodeRecords(records)
        )
        val exportedEntries = JSONArray()
        validated.forEach { entry ->
            val permissions = JSONArray()
            entry.snapshot.appDeclaredPermissions.forEach { permissions.put(it) }
            exportedEntries.put(
                JSONObject()
                    .put("observed_at", entry.observedAt.toString())
                    .put("location_services", normalizeToggle(entry.snapshot.locationServices))
                    .put("wifi_radio", normalizeToggle(entry.snapshot.wifiRadio))
                    .put("private_dns_mode", redactPrivateDns(entry.snapshot.privateDns))
                    .put("active_default_network_vpn", normalizeVpnState(entry.snapshot.activeDefaultNetworkVpn))
                    .put("app_declared_permissions", permissions)
            )
        }

        val json = JSONObject()
            .put("format", "privacage-device-privacy-timeline-export")
            .put("schema_version", 1)
            .put("source", "user_saved_device_privacy_timeline")
            .put("generated_at", generatedAt.toString())
            .put("generated_at_basis", "device_clock")
            .put("record_order", "user_save_order")
            .put("record_count", validated.size)
            .put(
                "redactions",
                JSONObject()
                    .put("private_dns_provider_hostname", true)
                    .put("record_ids", true)
                    .put("coordinates", true)
                    .put("wifi_ssids_and_scan_results", true)
                    .put("other_app_permissions", true)
                    .put("device_identifiers", true)
            )
            .put("encryption", "none")
            .put("signature", "none")
            .put("records", exportedEntries)
            .put(
                "limitations",
                JSONArray()
                    .put("Observation timestamps use the device clock and are not trusted time.")
                    .put("Records are user-save snapshots, not a background event feed or setting-change history.")
                    .put("The export cannot identify who changed a setting or when the setting changed.")
                    .put("Only the listed Android-exposed settings and PrivaCage's own declared permissions are included.")
                    .put("The JSON is plaintext, unsigned and not tamper-evident; the selected provider may sync it.")
            )
            .toString(2) + "\n"

        val bytes = json.toByteArray(StandardCharsets.UTF_8)
        try {
            require(bytes.size <= MAX_EXPORT_BYTES) {
                "Device privacy timeline export exceeds the 512 KiB output limit."
            }
        } finally {
            bytes.fill(0)
        }

        return DevicePrivacyTimelineExportResult(
            json = json,
            previewText = renderPreview(validated.size, generatedAt),
            recordCount = validated.size
        )
    }

    private fun normalizeToggle(value: String): String = when (value) {
        "ON", "OFF", "Not readable by this app" -> value
        "Unavailable" -> "Unavailable"
        else -> if (value.startsWith("Unavailable (")) "Unavailable" else "Unknown / redacted"
    }

    private fun normalizeVpnState(value: String): String = when (value) {
        "No active default network",
        "VPN transport detected",
        "No VPN transport detected on the active default network",
        "Not readable by this app" -> value
        "Unavailable" -> "Unavailable"
        else -> if (value.startsWith("Unavailable (")) "Unavailable" else "Unknown / redacted"
    }

    private fun redactPrivateDns(value: String): String = when {
        value == "OFF" -> "OFF"
        value == "Automatic / opportunistic" -> "Automatic / opportunistic"
        value == "Strict mode selected; provider hostname unavailable" ->
            "Strict mode; provider hostname unavailable"
        value.startsWith("Strict mode:") -> "Strict mode; provider hostname redacted"
        value == "Unknown / not exposed by this Android build" -> value
        value == "Not readable by this app" -> value
        value == "Unrecognized mode (not assumed secure)" -> value
        value == "Unavailable" || value.startsWith("Unavailable (") -> "Unavailable"
        else -> "Unknown / redacted"
    }

    private fun renderPreview(recordCount: Int, generatedAt: Instant): String = buildString {
        appendLine("REDACTED DEVICE PRIVACY TIMELINE EXPORT")
        appendLine("Observations: $recordCount (user-save order)")
        appendLine("Generated at (device clock): $generatedAt")
        appendLine("Private DNS provider hostnames: ALWAYS REDACTED")
        appendLine("Local record IDs: OMITTED")
        appendLine("PrivaCage's own declared permission names: INCLUDED")
        appendLine()
        appendLine("The file is plaintext JSON. It is not encrypted, signed or tamper-evident.")
        appendLine("The selected document provider may sync or otherwise process the file.")
        append("This export is not a background event feed and cannot establish who changed a setting or when.")
    }
}
