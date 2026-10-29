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
    fun historyRecordsMustMatchTheExactKnownSchema() {
        val extraField = """[{"timestamp":"2026-10-26T10:00:00Z","domain":"example.org","action":"ALLOW","socket_owner":"Unknown","raw_packet":"private"}]"""
        val missingField = """[{"timestamp":"2026-10-26T10:00:00Z","domain":"example.org","action":"ALLOW"}]"""
        val wrongType = """[{"timestamp":"2026-10-26T10:00:00Z","domain":"example.org","action":true,"socket_owner":"Unknown"}]"""
        assertNull(LocalDnsEventHistory.parseStoredEvents(extraField))
        assertNull(LocalDnsEventHistory.parseStoredEvents(missingField))
        assertNull(LocalDnsEventHistory.parseStoredEvents(wrongType))
    }

    @Test
    fun rejectsNonCanonicalTimestampsAndControlCharactersInStoredLabels() {
        val nonCanonicalTimestamp = """[{"timestamp":"2026-10-26T10:00:00+00:00","domain":"example.org","action":"ALLOW","socket_owner":"Unknown"}]"""
        val controlInOwner = """[{"timestamp":"2026-10-26T10:00:00Z","domain":"example.org","action":"ALLOW","socket_owner":"Unknown\nprivate"}]"""
        assertNull(LocalDnsEventHistory.parseStoredEvents(nonCanonicalTimestamp))
        assertNull(LocalDnsEventHistory.parseStoredEvents(controlInOwner))
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
        // The stored history parser rejects invalid timestamps; pruning must not mutate the source text.
        assertNull(LocalDnsEventHistory.parseStoredEvents(stored))
        assertTrue(stored.contains("expired.example"))
        assertTrue(stored.contains("invalid-time.example"))
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

    @Test
    fun storedHistoryRejectsRecordsAboveTheEventCeilingWithoutPruningEvidence() {
        val now = Instant.parse("2026-10-26T12:00:00Z")
        val hundred = events(*Array(100) { index ->
            event(now.minusSeconds(index.toLong()).toString(), "entry$index.example")
        })
        assertEquals(100, LocalDnsEventHistory.parseStoredEvents(hundred)?.length())

        val oneHundredOne = events(*Array(101) { index ->
            event(now.minusSeconds(index.toLong()).toString(), "entry$index.example")
        })
        assertNull(LocalDnsEventHistory.parseStoredEvents(oneHundredOne))
        assertNull(LocalDnsEventHistory.pruneExpiredEvents(oneHundredOne, now, 7))
        assertTrue(oneHundredOne.contains("entry0.example"))
        assertTrue(oneHundredOne.contains("entry100.example"))
    }

    @Test
    fun seededLocalHistoryMutationsNeverThrowOrChangeTheStoredSourceText() {
        val source = events(
            event("2026-10-26T10:00:00Z", "first.example"),
            event("2026-10-26T11:00:00Z", "second.example")
        )
        val random = java.util.Random(0x50434147454L)
        repeat(256) { caseIndex ->
            val mutated = source.toCharArray()
            val index = random.nextInt(mutated.size)
            mutated[index] = (mutated[index].code xor (1 shl random.nextInt(7))).toChar()
            val result = runCatching { LocalDnsEventHistory.parseStoredEvents(mutated.concatToString()) }
            assertTrue("History parser threw for mutation $caseIndex", result.isSuccess)
        }
        assertTrue(source.contains("first.example"))
        assertTrue(source.contains("second.example"))
    }

    @Test
    fun localHistoryEnforcesExactUtf8ByteBoundaryBeforeParsing() {
        val exact = "[" + " ".repeat(256 * 1024 - 2) + "]"
        assertEquals(256 * 1024, exact.toByteArray(Charsets.UTF_8).size)
        assertEquals(0, LocalDnsEventHistory.parseStoredEvents(exact)?.length())
        assertNull(LocalDnsEventHistory.parseStoredEvents(exact + " "))
    }
}
