package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsHistoryDomainClassifierTest {
    @Test
    fun matchesHostnameCaseInsensitivelyAndIgnoresOneRootDot() {
        val result = DnsHistoryDomainClassifier.classify(
            "WWW.CLARITY.MS.",
            listOf(signature(domains = listOf("www.clarity.ms")))
        )

        assertEquals("www.clarity.ms", result.normalizedHostname)
        assertEquals(1, result.matches.size)
        assertEquals("microsoft-clarity-collection", result.matches.single().recordId)
        assertEquals("www.clarity.ms", result.matches.single().matchedDomain)
    }

    @Test
    fun matchesSubdomainsOnlyAtDnsLabelBoundaries() {
        val catalog = listOf(signature(domains = listOf("google-analytics.com")))

        val subdomain = DnsHistoryDomainClassifier.classify("region1.google-analytics.com", catalog)
        val suffixConfusion = DnsHistoryDomainClassifier.classify("google-analytics.com.attacker.invalid", catalog)

        assertEquals(1, subdomain.matches.size)
        assertTrue(suffixConfusion.matches.isEmpty())
    }

    @Test
    fun returnsReviewAndRetiredStatusesWithoutPromotingThemToActive() {
        val catalog = listOf(
            signature(id = "review-entry", status = "review", domains = listOf("review.example")),
            signature(id = "retired-entry", status = "retired", domains = listOf("retired.example"))
        )

        val review = DnsHistoryDomainClassifier.classify("review.example", catalog)
        val retired = DnsHistoryDomainClassifier.classify("retired.example", catalog)

        assertEquals("review", review.matches.single().status)
        assertTrue(review.summary().contains("review-only indicator"))
        assertEquals("retired", retired.matches.single().status)
        assertTrue(retired.summary().contains("retired indicator"))
    }

    @Test
    fun choosesMostSpecificDomainForDuplicatePatternsInOneRecord() {
        val record = signature(domains = listOf("example", "sub.example"))
        val result = DnsHistoryDomainClassifier.classify("sub.example", listOf(record))

        assertEquals(1, result.matches.size)
        assertEquals("sub.example", result.matches.single().matchedDomain)
    }

    @Test
    fun ignoresSdkClassPatternsForDnsHostnameClassification() {
        val record = signature(domains = emptyList(), sdkPatterns = listOf("com.example.analytics.Client"))
        val result = DnsHistoryDomainClassifier.classify("api.example.org", listOf(record))

        assertTrue(result.matches.isEmpty())
    }

    @Test
    fun reportsUnavailableCatalogueSeparatelyFromNoMatch() {
        val unavailable = DnsHistoryDomainClassifier.classify("safe-looking.example", null)
        val noMatch = DnsHistoryDomainClassifier.classify("safe-looking.example", emptyList())

        assertFalse(unavailable.catalogAvailable)
        assertTrue(unavailable.summary().contains("unavailable"))
        assertTrue(noMatch.catalogAvailable)
        assertTrue(noMatch.summary().contains("does not prove"))
    }

    @Test
    fun invalidHostnamesNeverMatchAValidCatalogDomain() {
        val catalog = listOf(signature(domains = listOf("example.com")))
        val invalid = listOf(
            "https://example.com",
            "example.com:443",
            "example..com",
            "-example.com",
            "example.com..",
            " example.com"
        )

        invalid.forEach { hostname ->
            val result = DnsHistoryDomainClassifier.classify(hostname, catalog)
            assertNull("Expected invalid host to be rejected: $hostname", result.normalizedHostname)
            assertTrue(result.matches.isEmpty())
            assertTrue(result.summary().contains("not a valid DNS hostname"))
        }
    }

    @Test
    fun normalizesInternationalizedDomainNamesToAsciiBeforeMatching() {
        val result = DnsHistoryDomainClassifier.classify(
            "bücher.example",
            listOf(signature(domains = listOf("xn--bcher-kva.example")))
        )

        assertEquals("xn--bcher-kva.example", result.normalizedHostname)
        assertEquals(1, result.matches.size)
    }

    @Test
    fun summarizesAdditionalMatchesWithoutDroppingThemFromTheModel() {
        val catalog = (1..5).map { index ->
            signature(
                id = "tracker-$index",
                name = "Tracker $index",
                domains = listOf("common.example")
            )
        }
        val result = DnsHistoryDomainClassifier.classify("common.example", catalog)

        assertEquals(5, result.matches.size)
        assertTrue(result.summary(maxMatches = 2).contains("Additional catalogue matches omitted from this view: 3"))
    }

    private fun signature(
        id: String = "microsoft-clarity-collection",
        name: String = "Microsoft Clarity collection endpoint",
        domains: List<String> = listOf("www.clarity.ms"),
        sdkPatterns: List<String> = emptyList(),
        status: String = "active",
        confidence: String = "high"
    ) = TrackerSignature(
        id = id,
        name = name,
        category = "analytics",
        domains = domains,
        sdkPatterns = sdkPatterns,
        confidence = confidence,
        status = status,
        lastVerified = "2026-10-23",
        evidence = listOf(TrackerEvidence("https://example.org/evidence", "Test source"))
    )
}
