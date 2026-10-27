package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.time.Duration
import java.time.Instant

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
    fun duplicateEventKeysInvalidateHistoryWithoutDroppingTheDuplicateSilently() {
        val stored = """[{"timestamp":"2026-10-26T10:00:00Z","timestamp":"2026-10-27T10:00:00Z","domain":"example.org","action":"ALLOW","socket_owner":"Unknown"}]"""
        assertNull(LocalDnsEventHistory.parseStoredEvents(stored))
    }

    @Test
    fun oversizedStoredHistoryIsRejectedBeforeJsonParsing() {
        val oversized = "[" + " ".repeat(256 * 1024) + "]"

        assertNull(LocalDnsEventHistory.parseStoredEvents(oversized))
    }

    @Test
    fun retentionRemovesExpiredEventsAndKeepsTheExactCutoffBoundary() {
        val now = Instant.parse("2026-10-26T12:00:00Z")
        val expired = event(now.minus(Duration.ofDays(8)).toString(), "expired.example")
        val atCutoff = event(now.minus(Duration.ofDays(7)).toString(), "cutoff.example")
        val recent = event(now.minus(Duration.ofDays(1)).toString(), "recent.example")

        val retained = LocalDnsEventHistory.pruneExpiredEvents(events(expired, atCutoff, recent), now, 7)

        assertNotNull(retained)
        assertEquals(2, retained?.length())
        assertEquals("cutoff.example", retained?.optJSONObject(0)?.optString("domain"))
        assertEquals("recent.example", retained?.optJSONObject(1)?.optString("domain"))
    }

    @Test
    fun retentionCanBeConfiguredForTwentyFourHours() {
        val now = Instant.parse("2026-10-26T12:00:00Z")
        val yesterday = event(now.minus(Duration.ofHours(23)).toString(), "yesterday.example")
        val older = event(now.minus(Duration.ofHours(25)).toString(), "older.example")

        val retained = LocalDnsEventHistory.pruneExpiredEvents(events(yesterday, older), now, 1)

        assertNotNull(retained)
        assertEquals(1, retained?.length())
        assertEquals("yesterday.example", retained?.optJSONObject(0)?.optString("domain"))
    }

    @Test
    fun invalidStoredTimestampAbortsTheEntirePruneWithoutDroppingOtherRecords() {
        val now = Instant.parse("2026-10-26T12:00:00Z")
        val expired = event(now.minus(Duration.ofDays(9)).toString(), "expired.example")
        val invalid = event("not-an-instant", "invalid-time.example")
        val stored = events(expired, invalid)

        assertNull(LocalDnsEventHistory.pruneExpiredEvents(stored, now, 1))
        assertEquals(2, LocalDnsEventHistory.parseStoredEvents(stored)?.length())
    }

    @Test
    fun invalidRetentionValueFallsBackToTheSafeSevenDayDefault() {
        assertEquals(7, LocalDnsEventHistory.normalizeRetentionDays(0))
        assertEquals(7, LocalDnsEventHistory.normalizeRetentionDays(365))
    }

    @Test
    fun futureDatedEventIsRetainedRatherThanSilentlyDiscarded() {
        val now = Instant.parse("2026-10-26T12:00:00Z")
        val future = event(now.plus(Duration.ofDays(1)).toString(), "future.example")

        val retained = LocalDnsEventHistory.pruneExpiredEvents(events(future), now, 7)

        assertEquals(1, retained?.length())
        assertEquals("future.example", retained?.optJSONObject(0)?.optString("domain"))
    }

    private fun event(timestamp: String, domain: String = "example.org"): String =
        """{"timestamp":"$timestamp","domain":"$domain","action":"ALLOW","socket_owner":"Unknown"}"""

    private fun events(vararg records: String): String = records.joinToString(",", "[", "]")

    @Test
    fun oversizedUtf8HistoryIsRejectedEvenBelowTheCharacterLimit() {
        val oversized = "[\"" + "é".repeat(140_000) + "\"]"

        assertTrue(oversized.length < 256 * 1024)
        assertTrue(oversized.toByteArray(Charsets.UTF_8).size > 256 * 1024)
        assertNull(LocalDnsEventHistory.parseStoredEvents(oversized))
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
