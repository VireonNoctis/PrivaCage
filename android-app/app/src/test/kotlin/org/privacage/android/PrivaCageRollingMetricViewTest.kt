package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PrivaCageRollingMetricViewTest {
    @Test
    fun formatsZeroWithoutDroppingTheValue() {
        assertEquals("0", formatCounterValue(0L))
    }

    @Test
    fun formatsLargeCountsWithStableGrouping() {
        assertEquals("1,234,567", formatCounterValue(1_234_567L))
    }

    @Test
    fun rejectsNegativeValuesInsteadOfDisplayingAnInvalidCounter() {
        assertThrows(IllegalArgumentException::class.java) {
            formatCounterValue(-1L)
        }
    }
}
