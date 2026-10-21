package org.privacage.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsPolicyEngineTest {

    @Test
    fun blocksExactDomain() {
        val result = DnsPolicyEngine(setOf("tracker.example")).evaluate(query("tracker.example"))
        val blocked = assertIs<DnsDecision.Block>(result)
        assertEquals("tracker.example", blocked.matchedRule)
        assertEquals("tracker.example", blocked.question.name)
    }

    @Test
    fun blocksSubdomainsButNotLookalikeSuffixes() {
        val engine = DnsPolicyEngine(setOf("example.org"))
        assertIs<DnsDecision.Block>(engine.evaluate(query("cdn.example.org")))
        assertIs<DnsDecision.Allow>(engine.evaluate(query("notexample.org")))
        assertIs<DnsDecision.Allow>(engine.evaluate(query("example.org.attacker.test")))
    }

    @Test
    fun normalizesCaseAndTrailingDotInRules() {
        val result = DnsPolicyEngine(setOf("Tracker.Example.")).evaluate(query("TRACKER.EXAMPLE"))
        assertIs<DnsDecision.Block>(result)
    }

    @Test
    fun allowsUnrelatedDomain() {
        assertIs<DnsDecision.Allow>(
            DnsPolicyEngine(setOf("ads.example")).evaluate(query("news.example.org"))
        )
    }

    @Test
    fun rejectsTruncatedHeader() {
        val result = DnsPolicyEngine(setOf("tracker.example")).evaluate(ByteArray(4))
        assertIs<DnsDecision.Malformed>(result)
    }

    @Test
    fun rejectsResponsePassedAsQuery() {
        val message = query("tracker.example")
        message[2] = (message[2].toInt() or 0x80).toByte()
        assertIs<DnsDecision.Malformed>(DnsPolicyEngine(setOf("tracker.example")).evaluate(message))
    }

    @Test
    fun rejectsCompressedQname() {
        val message = query("tracker.example")
        message[12] = 0xc0.toByte()
        message[13] = 0x0c
        assertIs<DnsDecision.Malformed>(DnsPolicyEngine(setOf("tracker.example")).evaluate(message))
    }

    @Test
    fun rejectsTrailingRecordsRatherThanIgnoringThem() {
        val message = query("tracker.example") + byteArrayOf(0, 0, 0, 0)
        assertIs<DnsDecision.Malformed>(DnsPolicyEngine(setOf("tracker.example")).evaluate(message))
    }

    @Test
    fun rejectsInvalidBlocklistRuleAtConstruction() {
        val exception = runCatching {
            DnsPolicyEngine(setOf("https://tracker.example/path"))
        }.exceptionOrNull()
        assertTrue(exception is IllegalArgumentException)
    }

    private fun query(name: String, type: Int = 1): ByteArray {
        val qname = name.trimEnd('.').split('.').flatMap { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            listOf(bytes.size.toByte()) + bytes.toList()
        } + listOf(0.toByte())

        val header = byteArrayOf(
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        )
        val questionTail = byteArrayOf(
            ((type shr 8) and 0xff).toByte(), (type and 0xff).toByte(),
            0x00, 0x01
        )
        return header + qname.toByteArray() + questionTail
    }
}
