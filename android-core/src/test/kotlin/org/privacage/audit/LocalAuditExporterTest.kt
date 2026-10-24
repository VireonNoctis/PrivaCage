package org.privacage.audit

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LocalAuditExporterTest {
    private val utc = ZoneId.of("UTC")
    private val generatedAt = Instant.parse("2026-10-24T12:00:00Z")
    private val date = LocalDate.parse("2026-10-24")

    @Test
    fun redactsHostnamesAndOwnerLabelsByDefault() {
        val result = LocalAuditExporter.prepare(
            listOf(event("private.example", "UID 10123: secret.package")),
            request(),
            generatedAt
        )
        assertEquals(1, result.eventCount)
        assertFalse(result.json.contains("private.example"))
        assertFalse(result.json.contains("secret.package"))
        assertTrue(result.json.contains("\"queried_hostnames\": true"))
        assertTrue(result.json.contains("\"socket_owner_labels\": true"))
        assertTrue(result.json.contains("\"device_identifiers\": true"))
        assertTrue(result.previewText.contains("queried hostnames: REDACTED"))
        assertTrue(result.previewText.contains("socket-owner labels: REDACTED"))
    }

    @Test
    fun includesSensitiveFieldsOnlyWhenExplicitlySelected() {
        val result = LocalAuditExporter.prepare(
            listOf(event("chosen.example", "UID 10123: chosen.package")),
            request(includeHostnames = true, includeOwners = true),
            generatedAt
        )
        assertTrue(result.json.contains("chosen.example"))
        assertTrue(result.json.contains("chosen.package"))
        assertTrue(result.json.contains("\"queried_hostnames\": false"))
        assertTrue(result.json.contains("\"socket_owner_labels\": false"))
        assertTrue(result.previewText.contains("chosen.example"))
    }

    @Test
    fun filtersByInclusiveDatesAndSelectedCategories() {
        val input = listOf(
            event("first.example", action = "BLOCKED", timestamp = "2026-10-23T23:59:59Z"),
            event("blocked.example", action = "BLOCKED", timestamp = "2026-10-24T01:00:00Z"),
            event("forwarded.example", action = "FORWARDED", timestamp = "2026-10-24T02:00:00Z"),
            event("last.example", action = "FORWARDED", timestamp = "2026-10-25T00:00:00Z")
        )
        val result = LocalAuditExporter.prepare(
            input,
            request(categories = setOf("BLOCKED"), includeHostnames = true),
            generatedAt
        )
        assertEquals(1, result.eventCount)
        assertEquals(3, result.recordsExcludedByFilters)
        assertTrue(result.json.contains("blocked.example"))
        assertTrue(result.json.contains("\"category\": \"BLOCKED\""))
        assertFalse(result.json.contains("forwarded.example"))
    }

    @Test
    fun skipsMalformedTimestampsAndUnsupportedCategoriesExplicitly() {
        val input = listOf(
            event("valid.example"),
            event("bad-time.example", timestamp = "not-a-timestamp"),
            event("unknown.example", action = "UNKNOWN")
        )
        val result = LocalAuditExporter.prepare(input, request(), generatedAt)
        assertEquals(1, result.eventCount)
        assertEquals(2, result.recordsSkippedInvalid)
        assertTrue(result.json.contains("\"records_skipped_invalid\": 2"))
    }

    @Test
    fun escapesControlCharactersInOptionalUserData() {
        val result = LocalAuditExporter.prepare(
            listOf(event("quote\"and\nnewline.example", "owner\\line\nnext")),
            request(includeHostnames = true, includeOwners = true),
            generatedAt
        )
        assertTrue(result.json.contains("quote\\\"and\\nnewline.example"))
        assertTrue(result.json.contains("owner\\\\line\\nnext"))
        assertFalse(result.json.contains("quote\"and\nnewline.example"))
    }

    @Test
    fun rejectsEmptyCategorySelection() {
        assertFailsWith<IllegalArgumentException> {
            LocalAuditExporter.prepare(emptyList(), request(categories = emptySet()), generatedAt)
        }
    }

    @Test
    fun rejectsReversedDateRange() {
        assertFailsWith<IllegalArgumentException> {
            LocalAuditExporter.prepare(
                emptyList(),
                AuditExportRequest(date, date.minusDays(1), setOf("BLOCKED"), timeZone = utc),
                generatedAt
            )
        }
    }

    private fun request(
        categories: Set<String> = setOf("BLOCKED", "FORWARDED"),
        includeHostnames: Boolean = false,
        includeOwners: Boolean = false
    ) = AuditExportRequest(
        startDate = date,
        endDate = date,
        categories = categories,
        includeHostnames = includeHostnames,
        includeSocketOwnerLabels = includeOwners,
        timeZone = utc
    )

    private fun event(
        hostname: String,
        owner: String = "Android system resolver (initiating app not identifiable)",
        action: String = "FORWARDED",
        timestamp: String = "2026-10-24T10:00:00Z"
    ) = AuditExportEvent(timestamp, action, hostname, owner)
}
