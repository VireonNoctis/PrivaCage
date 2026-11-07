package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MonitoringAccessAuditTest {
    @Test
    fun emptyAndNullSettingsRepresentNoEnabledComponents() {
        listOf(null, "").forEach { raw ->
            val parsed = MonitoringAccessAudit.parseEnabledComponentSetting(raw)
            assertTrue(parsed.isComplete)
            assertTrue(parsed.components.isEmpty())
            assertEquals(0, parsed.invalidEntryCount)
        }
    }

    @Test
    fun whitespaceOnlySettingIsReportedAsMalformedInsteadOfEmptySuccess() {
        val parsed = MonitoringAccessAudit.parseEnabledComponentSetting("   ")
        assertFalse(parsed.isComplete)
        assertTrue(parsed.components.isEmpty())
        assertEquals(1, parsed.invalidEntryCount)
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
