package org.privacage.android

import org.junit.Assert.assertTrue
import org.junit.Test

class AdvancedProtectionModeStatusTest {
    @Test
    fun preAndroid16IsExplicitlyUnavailable() {
        val result = AdvancedProtectionModeStatus.describe(35, true)
        assertTrue(result.contains("UNAVAILABLE"))
        assertTrue(result.contains("Android 16"))
    }

    @Test
    fun supportedModeReportsEnabledAndDisabledSeparately() {
        assertTrue(AdvancedProtectionModeStatus.describe(36, true).contains("ENABLED"))
        assertTrue(AdvancedProtectionModeStatus.describe(36, false).contains("DISABLED"))
    }

    @Test
    fun missingManagerStateIsNotMisreportedAsDisabled() {
        assertTrue(AdvancedProtectionModeStatus.describe(36, null).contains("UNAVAILABLE"))
    }
}
