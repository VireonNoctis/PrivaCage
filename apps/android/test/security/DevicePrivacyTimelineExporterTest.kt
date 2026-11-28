package org.privacage.android

import java.time.Instant
import java.util.UUID
import org.json.JSONObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DevicePrivacyTimelineExporterTest {
    private val generatedAt = Instant.parse("2026-11-26T09:00:00Z")

    private fun entry(
        id: String = UUID.randomUUID().toString(),
        privateDns: String = "Automatic / opportunistic",
        location: String = "OFF",
        wifi: String = "ON",
        vpn: String = "No VPN transport detected on the active default network",
        permissions: List<String> = listOf("android.permission.INTERNET — normal; DNS forwarding")
    ) = DevicePrivacyTimelineEntry(
        id = id,
        observedAt = Instant.parse("2026-11-25T09:00:00Z"),
        snapshot = DevicePrivacySnapshot(location, wifi, privateDns, vpn, permissions)
    )

    @Test
    fun exportAlwaysRedactsPrivateDnsHostnameAndOmitsLocalRecordIds() {
        val id = "00000000-0000-4000-8000-000000000001"
        val result = DevicePrivacyTimelineExporter.prepare(
            listOf(entry(id = id, privateDns = "Strict mode: resolver.private.example")),
            generatedAt
        )
        val root = JSONObject(result.json)
        val record = root.getJSONArray("records").getJSONObject(0)

        assertEquals(1, result.recordCount)
        assertEquals("Strict mode; provider hostname redacted", record.getString("private_dns_mode"))
        assertFalse(result.json.contains("resolver.private.example"))
        assertFalse(result.json.contains(id))
        assertFalse(record.has("id"))
        assertTrue(root.getJSONObject("redactions").getBoolean("private_dns_provider_hostname"))
        assertTrue(root.getJSONObject("redactions").getBoolean("record_ids"))
        assertTrue(record.getJSONArray("app_declared_permissions").getString(0).contains("android.permission.INTERNET"))
        assertTrue(result.previewText.contains("ALWAYS REDACTED"))
        assertTrue(result.previewText.contains("not encrypted, signed or tamper-evident"))
    }

    @Test
    fun unknownPrivateDnsValuesAreReplacedRatherThanCopiedToTheExport() {
        val result = DevicePrivacyTimelineExporter.prepare(
            listOf(entry(privateDns = "untrusted-provider.example")),
            generatedAt
        )
        val record = JSONObject(result.json).getJSONArray("records").getJSONObject(0)

        assertEquals("Unknown / redacted", record.getString("private_dns_mode"))
        assertFalse(result.json.contains("untrusted-provider.example"))
    }

    @Test
    fun emptyHistoryProducesAnExplicitEmptyReport() {
        val result = DevicePrivacyTimelineExporter.prepare(emptyList(), generatedAt)
        val root = JSONObject(result.json)

        assertEquals(0, result.recordCount)
        assertEquals(0, root.getInt("record_count"))
        assertEquals(0, root.getJSONArray("records").length())
        assertTrue(result.previewText.contains("Observations: 0"))
    }

    @Test
    fun exporterRetainsStoreBoundsAndRejectsDisplayControlCharacters() {
        val tooMany = (0..DevicePrivacyTimelineStore.MAX_RECORDS).map { index ->
            entry(id = UUID(0L, index.toLong() + 1L).toString())
        }
        assertFailsWith<IllegalArgumentException> {
            DevicePrivacyTimelineExporter.prepare(tooMany, generatedAt)
        }

        assertFailsWith<IllegalStateException> {
            DevicePrivacyTimelineExporter.prepare(
                listOf(entry(privateDns = "Strict mode: resolver\u202E.example")),
                generatedAt
            )
        }
    }

    @Test
    fun unknownDeviceStatesAreNotCopiedAsAuthoritativeValues() {
        val result = DevicePrivacyTimelineExporter.prepare(
            listOf(entry(location = "spoofed state", wifi = "unexpected", vpn = "unknown owner")),
            generatedAt
        )
        val record = JSONObject(result.json).getJSONArray("records").getJSONObject(0)

        assertEquals("Unknown / redacted", record.getString("location_services"))
        assertEquals("Unknown / redacted", record.getString("wifi_radio"))
        assertEquals("Unknown / redacted", record.getString("active_default_network_vpn"))
    }
}
