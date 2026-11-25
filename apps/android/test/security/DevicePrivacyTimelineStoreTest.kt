package org.privacage.android

import java.time.Instant
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DevicePrivacyTimelineStoreTest {
    private fun snapshot(
        location: String = "OFF",
        wifi: String = "ON",
        privateDns: String = "Automatic / opportunistic",
        vpn: String = "No VPN transport detected on the active default network",
        permissions: List<String> = listOf("android.permission.INTERNET — normal; DNS forwarding")
    ) = DevicePrivacySnapshot(
        locationServices = location,
        wifiRadio = wifi,
        privateDns = privateDns,
        activeDefaultNetworkVpn = vpn,
        appDeclaredPermissions = permissions
    )

    private fun entry(
        id: String = UUID.randomUUID().toString(),
        observedAt: Instant = Instant.parse("2026-11-25T09:00:00Z"),
        value: DevicePrivacySnapshot = snapshot()
    ) = DevicePrivacyTimelineEntry(id, observedAt, value)

    @Test
    fun roundTripsCanonicalEncryptedStorePayload() {
        val original = listOf(entry())
        assertEquals(original, DevicePrivacyTimelineStore.decodeRecords(DevicePrivacyTimelineStore.encodeRecords(original)))
    }

    @Test
    fun rejectsDuplicateJsonKeysAndUnknownFields() {
        val valid = DevicePrivacyTimelineStore.encodeRecords(listOf(entry()))
        val duplicate = valid.replaceFirst(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1"
        )
        assertFailsWith<IllegalStateException> {
            DevicePrivacyTimelineStore.decodeRecords(duplicate)
        }
        val unknown = valid.replaceFirst("{", "{\"unexpected\":true,")
        assertFailsWith<IllegalStateException> {
            DevicePrivacyTimelineStore.decodeRecords(unknown)
        }
    }

    @Test
    fun rejectsNonCanonicalIdsAndTimestamps() {
        val valid = DevicePrivacyTimelineStore.encodeRecords(listOf(entry()))
        val badId = valid.replaceFirst(Regex("\"id\":\"[0-9a-f-]+\""), "\"id\":\"NOT-A-UUID\"")
        val badTimestamp = valid.replaceFirst(
            "2026-11-25T09:00:00Z",
            "2026-11-25"
        )
        assertFailsWith<IllegalStateException> {
            DevicePrivacyTimelineStore.decodeRecords(badId)
        }
        assertFailsWith<IllegalStateException> {
            DevicePrivacyTimelineStore.decodeRecords(badTimestamp)
        }
    }

    @Test
    fun rejectsDuplicateIdsAndInvalidText() {
        val same = entry(id = "00000000-0000-4000-8000-000000000001")
        val duplicateIds = DevicePrivacyTimelineStore.encodeRecords(listOf(same, same))
        assertFailsWith<IllegalStateException> {
            DevicePrivacyTimelineStore.decodeRecords(duplicateIds)
        }

        val valid = DevicePrivacyTimelineStore.encodeRecords(listOf(entry()))
        val controlCharacter = valid.replace(
            "wifi_radio\":\"ON",
            "wifi_radio\":\"line\\nfeed"
        )
        assertFailsWith<IllegalStateException> {
            DevicePrivacyTimelineStore.decodeRecords(controlCharacter)
        }
    }

    @Test
    fun refusesMoreThanThirtyRecords() {
        val records = (0..DevicePrivacyTimelineStore.MAX_RECORDS).map { index ->
            entry(
                id = UUID(0L, index.toLong() + 1L).toString(),
                observedAt = Instant.parse("2026-11-25T09:00:00Z").plusSeconds(index.toLong())
            )
        }
        assertFailsWith<IllegalArgumentException> {
            DevicePrivacyTimelineStore.encodeRecords(records)
        }
    }

    @Test
    fun appendRetainsOnlyTheNewestThirtyObservations() {
        val initial = (0 until DevicePrivacyTimelineStore.MAX_RECORDS).map { index ->
            entry(
                id = UUID(0L, index.toLong() + 1L).toString(),
                observedAt = Instant.parse("2026-11-25T09:00:00Z").plusSeconds(index.toLong())
            )
        }
        val updated = DevicePrivacyTimelineStore.appendRecord(
            initial,
            snapshot(location = "ON"),
            Instant.parse("2026-11-25T10:00:00Z")
        )
        assertEquals(DevicePrivacyTimelineStore.MAX_RECORDS, updated.size)
        assertFalse(updated.any { it.id == initial.first().id })
        assertEquals("ON", updated.last().snapshot.locationServices)
    }

    @Test
    fun reportsOnlyDifferencesBetweenExposedValues() {
        val changes = DevicePrivacyTimelineStore.changesBetween(
            snapshot(),
            snapshot(location = "ON", privateDns = "Strict mode: dns.example")
        )
        assertEquals(2, changes.size)
        assertTrue(changes.any { it.contains("Location services: OFF → ON") })
        assertTrue(changes.any { it.contains("Android Private DNS") })
    }

    @Test
    fun detectsChangesToPrivaCagePermissionDeclarationsWithoutClaimingOtherApps() {
        val changes = DevicePrivacyTimelineStore.changesBetween(
            snapshot(),
            snapshot(permissions = listOf("android.permission.INTERNET — normal; DNS forwarding", "android.permission.CAMERA — dangerous"))
        )
        assertEquals(1, changes.size)
        assertTrue(changes.single().contains("PrivaCage's own declared-permission inventory"))
    }

    @Test
    fun emptyAndPopulatedHistoryRenderTheirScope() {
        assertTrue(DevicePrivacyTimelineStore.renderHistory(emptyList()).contains("does not create a history entry"))
        val rendered = DevicePrivacyTimelineStore.renderHistory(listOf(entry()))
        assertTrue(rendered.contains("user-saved observations"))
        assertTrue(rendered.contains("device clock"))
        assertTrue(rendered.contains("not a background event feed"))
    }
}
