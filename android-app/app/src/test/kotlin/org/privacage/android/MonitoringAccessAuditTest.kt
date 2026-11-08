package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MonitoringAccessAuditTest {
    @Test
    fun emptySettingParsesToNoEnabledComponents() {
        val parsed = MonitoringAccessAudit.parseEnabledComponentSetting("")
        assertTrue(parsed.isComplete)
        assertTrue(parsed.components.isEmpty())
        assertEquals(0, parsed.invalidEntryCount)
    }

    @Test
    fun missingNotificationListenerSettingIsUnavailableInsteadOfAnEmptySuccess() {
        val observation = MonitoringAccessAudit.notificationListenerObservation(null)
        assertEquals(MonitoringObservationStatus.UNAVAILABLE, observation.status)
        assertTrue(observation.components.isEmpty())
        assertTrue(observation.detail!!.contains("cannot distinguish no enabled listeners"))
    }

    @Test
    fun explicitEmptyNotificationListenerSettingIsAvailable() {
        val observation = MonitoringAccessAudit.notificationListenerObservation("")
        assertEquals(MonitoringObservationStatus.AVAILABLE, observation.status)
        assertTrue(observation.components.isEmpty())
        assertEquals(null, observation.detail)
    }

    @Test
    fun whitespaceOnlySettingIsReportedAsMalformedInsteadOfEmptySuccess() {
        val parsed = MonitoringAccessAudit.parseEnabledComponentSetting("   ")
        val observation = MonitoringAccessAudit.notificationListenerObservation("   ")
        assertFalse(parsed.isComplete)
        assertTrue(parsed.components.isEmpty())
        assertEquals(1, parsed.invalidEntryCount)
        assertEquals(MonitoringObservationStatus.PARTIAL, observation.status)
    }

    @Test
    fun parsesRelativeAndFullyQualifiedComponentNames() {
        val parsed = MonitoringAccessAudit.parseEnabledComponentSetting(
            "com.example.reader/.ReaderService:com.example.wear/com.example.wear.BridgeService"
        )
        assertTrue(parsed.isComplete)
        assertEquals(2, parsed.components.size)
        assertEquals("com.example.reader", parsed.components[0].packageName)
        assertEquals("com.example.reader.ReaderService", parsed.components[0].className)
        assertEquals("com.example.wear.BridgeService", parsed.components[1].className)
    }

    @Test
    fun deduplicatesRepeatedComponentsWithoutChangingOrder() {
        val parsed = MonitoringAccessAudit.parseEnabledComponentSetting(
            "com.example.reader/.ReaderService:com.example.reader/com.example.reader.ReaderService"
        )
        assertTrue(parsed.isComplete)
        assertEquals(1, parsed.components.size)
    }

    @Test
    fun malformedEntriesAreReportedAsPartialInsteadOfBeingTreatedAsAbsent() {
        val parsed = MonitoringAccessAudit.parseEnabledComponentSetting(
            "not-a-component:com.example.reader/.ReaderService:com.example.reader//Bad"
        )
        assertFalse(parsed.isComplete)
        assertEquals(1, parsed.components.size)
        assertEquals(2, parsed.invalidEntryCount)
    }

    @Test
    fun oversizedSettingIsRejectedWithoutReturningAnEmptySuccess() {
        val parsed = MonitoringAccessAudit.parseEnabledComponentSetting(
            "x".repeat(MonitoringAccessAudit.MAX_SETTING_CHARS + 1)
        )
        assertFalse(parsed.isComplete)
        assertTrue(parsed.inputTooLarge)
        assertTrue(parsed.components.isEmpty())
    }

    @Test
    fun componentCountIsBoundedAndTruncationIsExplicit() {
        val raw = (0..MonitoringAccessAudit.MAX_COMPONENTS)
            .joinToString(":") { "com.example.app" + it + "/.Listener" }
        val parsed = MonitoringAccessAudit.parseEnabledComponentSetting(raw)
        assertFalse(parsed.isComplete)
        assertTrue(parsed.truncated)
        assertEquals(MonitoringAccessAudit.MAX_COMPONENTS, parsed.components.size)
    }
}
