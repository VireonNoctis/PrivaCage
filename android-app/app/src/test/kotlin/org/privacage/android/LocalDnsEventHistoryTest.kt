package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class LocalDnsEventHistoryTest {
    @Test
    fun missingStoredValueStartsWithAnEmptyHistory() {
        assertEquals(0, LocalDnsEventHistory.parseStoredEvents(null)?.length())
    }

    @Test
    fun malformedJsonIsRejectedInsteadOfReplacingHistoryWithAnEmptyArray() {
        assertNull(LocalDnsEventHistory.parseStoredEvents("""{"timestamp":"""))
    }

    @Test
    fun nonObjectRecordsAreRejectedRatherThanDroppedDuringRetention() {
        val stored = """[{"timestamp":"2026-10-26T10:00:00Z","domain":"example.org","action":"ALLOW","socket_owner":"Unknown"},42]"""

        assertNull(LocalDnsEventHistory.parseStoredEvents(stored))
    }

    @Test
    fun validStoredHistoryCanBeReadWithoutChangingItsRecordCount() {
        val stored = """[{"timestamp":"2026-10-26T10:00:00Z","domain":"example.org","action":"ALLOW","socket_owner":"Unknown"}]"""

        val parsed = LocalDnsEventHistory.parseStoredEvents(stored)

        assertNotNull(parsed)
        assertEquals(1, parsed?.length())
        assertEquals("example.org", parsed?.optJSONObject(0)?.optString("domain"))
    }
}
