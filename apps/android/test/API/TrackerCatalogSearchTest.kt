package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TrackerCatalogSearchTest {
    private val catalog = listOf(
        TrackerSignature(
            id = "example-analytics",
            name = "Example Analytics",
            category = "analytics",
            domains = listOf("collect.example.test"),
            sdkPatterns = listOf("com.example.AnalyticsClient"),
            confidence = "medium",
            status = "active",
            lastVerified = "2026-10-25",
            evidence = listOf(TrackerEvidence("https://docs.example.test/sdk", "Documents event collection"))
        ),
        TrackerSignature(
            id = "example-crash",
            name = "Example Crash Reporter",
            category = "crash_reporting",
            domains = listOf("errors.example.test"),
            sdkPatterns = listOf("com.example.CrashReporter"),
            confidence = "low",
            status = "review",
            lastVerified = "2026-10-20",
            evidence = listOf(TrackerEvidence("https://docs.example.test/crash", "Crash diagnostics"))
        )
    )

    @Test
    fun blankQueryReturnsAllRecordsInOriginalOrder() {
        assertEquals(catalog, TrackerCatalogSearch.filter(catalog, "  "))
    }

    @Test
    fun searchesDomainsSdkClassesCategoryStatusAndEvidence() {
        assertEquals("example-analytics", TrackerCatalogSearch.filter(catalog, "collect.example.test").single().id)
        assertEquals("example-analytics", TrackerCatalogSearch.filter(catalog, "ANALYTICSCLIENT").single().id)
        assertEquals("example-crash", TrackerCatalogSearch.filter(catalog, "crash_reporting").single().id)
        assertEquals("example-crash", TrackerCatalogSearch.filter(catalog, "review").single().id)
        assertEquals("example-crash", TrackerCatalogSearch.filter(catalog, "Crash diagnostics").single().id)
    }

    @Test
    fun queryWithNoMatchReturnsAnEmptyList() {
        assertTrue(TrackerCatalogSearch.filter(catalog, "unseen.example").isEmpty())
    }
}
