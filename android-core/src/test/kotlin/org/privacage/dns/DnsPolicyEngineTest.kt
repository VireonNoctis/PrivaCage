package org.privacage.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
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
    fun previewsMostSpecificRuleWithoutSuffixFalsePositives() {
        val engine = DnsPolicyEngine(setOf("example.org", "api.example.org"))

        assertEquals("api.example.org", engine.matchingRuleForDomain("V1.API.EXAMPLE.ORG."))
        assertEquals("example.org", engine.matchingRuleForDomain("EXAMPLE.ORG"))
        assertNull(engine.matchingRuleForDomain("notexample.org"))
        assertNull(engine.matchingRuleForDomain("example.org.attacker.test"))
    }

    @Test
    fun resolvesMostSpecificMatchesAcrossTenThousandRules() {
        val rules = (0 until 10_000)
            .mapTo(mutableSetOf()) { index -> "tracker$index.example.test" }
            .apply {
                add("example.test")
                add("sdk.example.test")
            }
        val engine = DnsPolicyEngine(rules)

        assertEquals(
            "tracker9999.example.test",
            engine.matchingRuleForDomain("img.tracker9999.example.test")
        )
        assertEquals("sdk.example.test", engine.matchingRuleForDomain("sdk.example.test"))
        assertEquals("example.test", engine.matchingRuleForDomain("other.example.test"))
        assertNull(engine.matchingRuleForDomain("notexample.test"))
    }

    @Test
    fun rejectsRulesWithMultipleTrailingDots() {
        assertFailsWith<IllegalArgumentException> {
            DnsPolicyEngine(setOf("tracker.example.."))
        }
    }

    @Test
    fun allowsUnrelatedDomain() {
        assertIs<DnsDecision.Allow>(
            DnsPolicyEngine(setOf("ads.example")).evaluate(query("news.example.org"))
        )
    }

    @Test
    fun acceptsWellFormedEdnsOptRecord() {
        val result = DnsPolicyEngine(setOf("tracker.example")).evaluate(queryWithEdns("tracker.example"))
        val blocked = assertIs<DnsDecision.Block>(result)
        assertEquals("tracker.example", blocked.question.name)
    }

    @Test
    fun acceptsEdnsOptWithNoOptions() {
        assertIs<DnsDecision.Allow>(
            DnsPolicyEngine(emptySet()).evaluate(queryWithEdns("news.example.org", optionData = byteArrayOf()))
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
    fun rejectsEdnsOptionWithTruncatedData() {
        val malformedOption = byteArrayOf(0, 1, 0, 4, 1, 2)
        val result = DnsPolicyEngine(emptySet()).evaluate(
            queryWithEdns("news.example.org", optionData = malformedOption)
        )
        assertIs<DnsDecision.Malformed>(result)
    }

    @Test
    fun rejectsUnsupportedEdnsVersion() {
        val message = queryWithEdns("news.example.org")
        val optStart = questionEnd(message)
        message[optStart + 1 + 5] = 1
        assertIs<DnsDecision.Malformed>(DnsPolicyEngine(emptySet()).evaluate(message))
    }

    @Test
    fun rejectsNonOptAdditionalRecord() {
        val message = queryWithEdns("news.example.org")
        val optStart = questionEnd(message)
        message[optStart + 1] = 0
        message[optStart + 2] = 1
        assertIs<DnsDecision.Malformed>(DnsPolicyEngine(emptySet()).evaluate(message))
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

    @Test
    fun rejectsMultipleQuestionsAndUnsupportedQuestionClass() {
        val multiple = query("tracker.example").apply { this[5] = 2 }
        assertIs<DnsDecision.Malformed>(DnsPolicyEngine(setOf("tracker.example")).evaluate(multiple))

        val nonInternetClass = query("tracker.example").apply { this[this.size - 1] = 3 }
        assertIs<DnsDecision.Malformed>(
            DnsPolicyEngine(setOf("tracker.example")).evaluate(nonInternetClass)
        )
    }

    @Test
    fun rejectsReservedDnsFlagAndUnsupportedOpcode() {
        val reservedFlag = query("tracker.example").apply {
            this[3] = (this[3].toInt() or 0x40).toByte()
        }
        assertIs<DnsDecision.Malformed>(
            DnsPolicyEngine(setOf("tracker.example")).evaluate(reservedFlag)
        )

        val unsupportedOpcode = query("tracker.example").apply {
            this[2] = (this[2].toInt() or 0x08).toByte()
        }
        assertIs<DnsDecision.Malformed>(
            DnsPolicyEngine(setOf("tracker.example")).evaluate(unsupportedOpcode)
        )
    }

    @Test
    fun rejectsOverlongLabelsAndUnderscoreLabels() {
        val overlong = query("a".repeat(64) + ".example")
        assertIs<DnsDecision.Malformed>(DnsPolicyEngine(emptySet()).evaluate(overlong))

        val underscore = query("_service.example")
        assertIs<DnsDecision.Malformed>(DnsPolicyEngine(emptySet()).evaluate(underscore))
    }

    @Test
    fun seededMalformedQueriesNeverEscapeTheParserAsExceptions() {
        val engine = DnsPolicyEngine(setOf("tracker.example", "ads.example.org"))
        val random = java.util.Random(0x50434147454L)
        val seed = query("tracker.example")

        // Flip one bit at each byte boundary, including header counts, labels and question fields.
        for (index in seed.indices) {
            for (mask in listOf(1, 0x20, 0x80)) {
                val mutated = seed.copyOf()
                mutated[index] = (mutated[index].toInt() xor mask).toByte()
                val outcome = runCatching { engine.evaluate(mutated) }
                assertTrue("Parser threw on single-byte mutation at $index/$mask", outcome.isSuccess)
            }
        }

        repeat(512) { caseIndex ->
            val input = ByteArray(random.nextInt(0, 512))
            random.nextBytes(input)
            val outcome = runCatching { engine.evaluate(input) }
            assertTrue("Parser threw on deterministic malformed case $caseIndex", outcome.isSuccess)
        }
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

    private fun queryWithEdns(
        name: String,
        optionData: ByteArray = byteArrayOf(0xfd.toByte(), 0xe9.toByte(), 0, 2, 1, 2)
    ): ByteArray {
        val base = query(name)
        base[10] = 0
        base[11] = 1
        val optRecord = byteArrayOf(
            0,                         // root owner name
            0, 41,                      // TYPE = OPT
            0x04, 0xd0.toByte(),        // advertised UDP payload size = 1232
            0, 0, 0x80.toByte(), 0,      // extended RCODE, version, flags (DO bit)
            ((optionData.size shr 8) and 0xff).toByte(),
            (optionData.size and 0xff).toByte()
        ) + optionData
        return base + optRecord
    }

    private fun questionEnd(message: ByteArray): Int {
        var offset = 12
        while (message[offset].toInt() != 0) {
            offset += (message[offset].toInt() and 0xff) + 1
        }
        return offset + 1 + 4
    }
}
