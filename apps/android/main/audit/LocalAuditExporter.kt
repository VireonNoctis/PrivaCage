package org.privacage.audit

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeParseException
import java.util.Locale

data class AuditExportEvent(
    val timestamp: String,
    val category: String,
    val hostname: String,
    val socketOwnerLabel: String
)

data class AuditExportRequest(
    val startDate: LocalDate,
    val endDate: LocalDate,
    val categories: Set<String>,
    val includeHostnames: Boolean = false,
    val includeSocketOwnerLabels: Boolean = false,
    val timeZone: ZoneId = ZoneId.systemDefault()
)

data class AuditExportResult(
    val json: String,
    val eventCount: Int,
    val recordsRead: Int,
    val recordsSkippedInvalid: Int,
    val recordsExcludedByFilters: Int,
    val previewText: String,
    val chainHeadSha256: String
)

/**
 * Builds a deterministic, redaction-first export from the optional local DNS history.
 * It never adds packet contents, network addresses, internal paths, or device identifiers.
 */
object LocalAuditExporter {
    val supportedCategories: Set<String> = setOf("BLOCKED", "FORWARDED")
    private const val PREVIEW_EVENT_LIMIT = 5

    fun prepare(
        events: List<AuditExportEvent>,
        request: AuditExportRequest,
        generatedAt: Instant = Instant.now()
    ): AuditExportResult {
        require(!request.startDate.isAfter(request.endDate)) {
            "The start date must be on or before the end date."
        }
        require(request.categories.isNotEmpty()) {
            "Select at least one event category."
        }
        require(supportedCategories.containsAll(request.categories)) {
            "The selected event categories are unsupported."
        }

        var recordsSkippedInvalid = 0
        val valid = events.mapNotNull { event ->
            val timestamp = try {
                Instant.parse(event.timestamp)
            } catch (_: DateTimeParseException) {
                recordsSkippedInvalid++
                return@mapNotNull null
            }
            val category = event.category.trim().uppercase(Locale.ROOT)
            if (category !in supportedCategories) {
                recordsSkippedInvalid++
                return@mapNotNull null
            }
            NormalizedEvent(
                timestamp = timestamp,
                localDate = timestamp.atZone(request.timeZone).toLocalDate(),
                category = category,
                hostname = event.hostname,
                socketOwnerLabel = event.socketOwnerLabel
            )
        }.sortedWith(compareBy<NormalizedEvent> { it.timestamp }.thenBy { it.category })

        val selected = valid.filter { event ->
            !event.localDate.isBefore(request.startDate) &&
                !event.localDate.isAfter(request.endDate) &&
                event.category in request.categories
        }
        val excludedByFilters = valid.size - selected.size
        val chainRecords = AuditIntegrityChain.create(selected.map { event ->
            AuditChainInput(
                timestamp = event.timestamp.toString(),
                localDate = event.localDate.toString(),
                category = event.category,
                queriedHostname = if (request.includeHostnames) event.hostname else "[REDACTED]",
                socketOwnerLabel = if (request.includeSocketOwnerLabels) event.socketOwnerLabel else "[REDACTED]"
            )
        })
        val chainHead = chainRecords.lastOrNull()?.recordSha256 ?: AuditIntegrityChain.GENESIS_SHA256
        val json = renderJson(
            events.size, recordsSkippedInvalid, excludedByFilters, selected, request, generatedAt, chainRecords, chainHead
        )
        val preview = renderPreview(events.size, recordsSkippedInvalid, excludedByFilters, selected, request, generatedAt)

        return AuditExportResult(
            json = json,
            eventCount = selected.size,
            recordsRead = events.size,
            recordsSkippedInvalid = recordsSkippedInvalid,
            recordsExcludedByFilters = excludedByFilters,
            previewText = preview,
            chainHeadSha256 = chainHead
        )
    }

    private data class NormalizedEvent(
        val timestamp: Instant,
        val localDate: LocalDate,
        val category: String,
        val hostname: String,
        val socketOwnerLabel: String
    )

    private fun renderJson(
        recordsRead: Int,
        recordsSkippedInvalid: Int,
        recordsExcludedByFilters: Int,
        events: List<NormalizedEvent>,
        request: AuditExportRequest,
        generatedAt: Instant,
        chainRecords: List<AuditChainRecord>,
        chainHeadSha256: String
    ): String = buildString {
        append("{\n")
        append("  \"schema_version\": 1,\n")
        append("  \"source\": \"optional_local_dns_event_history\",\n")
        append("  \"generated_at\": ").append(jsonString(generatedAt.toString())).append(",\n")
        append("  \"filter_timezone\": ").append(jsonString(request.timeZone.id)).append(",\n")
        append("  \"date_range\": {\"start_inclusive\": ")
            .append(jsonString(request.startDate.toString()))
            .append(", \"end_inclusive\": ")
            .append(jsonString(request.endDate.toString()))
            .append("},\n")
        append("  \"selected_categories\": ")
            .append(jsonArray(request.categories.sorted().map(::jsonString))).append(",\n")
        append("  \"integrity\": {\"algorithm\": ").append(jsonString(AuditIntegrityChain.ALGORITHM))
            .append(", \"genesis_sha256\": ").append(jsonString(AuditIntegrityChain.GENESIS_SHA256))
            .append(", \"chain_head_sha256\": ").append(jsonString(chainHeadSha256))
            .append(", \"record_count\": ").append(chainRecords.size).append("},\n")
        append("  \"redactions\": {\n")
        append("    \"queried_hostnames\": ").append(!request.includeHostnames).append(",\n")
        append("    \"socket_owner_labels\": ").append(!request.includeSocketOwnerLabels).append(",\n")
        append("    \"device_identifiers\": true,\n")
        append("    \"internal_file_paths\": true,\n")
        append("    \"packet_payloads\": true\n")
        append("  },\n")
        append("  \"records_read\": ").append(recordsRead).append(",\n")
        append("  \"records_skipped_invalid\": ").append(recordsSkippedInvalid).append(",\n")
        append("  \"records_excluded_by_filters\": ").append(recordsExcludedByFilters).append(",\n")
        append("  \"event_count\": ").append(events.size).append(",\n")
        append("  \"events\": [")
        if (events.isNotEmpty()) append('\n')
        events.forEachIndexed { index, _ ->
            append("    ").append(eventJson(chainRecords[index]))
            if (index != events.lastIndex) append(',')
            append('\n')
        }
        if (events.isNotEmpty()) append("  ")
        append("]\n")
        append("}\n")
    }

    private fun renderPreview(
        recordsRead: Int,
        recordsSkippedInvalid: Int,
        recordsExcludedByFilters: Int,
        events: List<NormalizedEvent>,
        request: AuditExportRequest,
        generatedAt: Instant
    ): String = buildString {
        append("REDACTION PREVIEW — LOCAL DNS HISTORY\n")
        append("Generated: ").append(generatedAt).append('\n')
        append("Date range: ").append(request.startDate).append(" through ").append(request.endDate)
            .append(" (").append(request.timeZone.id).append(")\n")
        append("Categories: ").append(request.categories.sorted().joinToString(", ")).append('\n')
        append("Matching events: ").append(events.size).append('\n')
        append("Stored records examined: ").append(recordsRead).append('\n')
        append("Excluded by date/category: ").append(recordsExcludedByFilters).append('\n')
        append("Malformed/unsupported records skipped: ").append(recordsSkippedInvalid).append('\n')
        append("Queried hostnames: ").append(if (request.includeHostnames) "INCLUDED" else "REDACTED").append('\n')
        append("Socket-owner labels: ").append(if (request.includeSocketOwnerLabels) "INCLUDED" else "REDACTED").append('\n')
        append("Device identifiers, internal file paths and packet payloads: never exported\n")
        append("\nPreview of up to ").append(minOf(PREVIEW_EVENT_LIMIT, events.size)).append(" matching records:\n")
        if (events.isEmpty()) {
            append("No matching records. You can still save an empty report with its filter metadata.")
        } else {
            events.take(PREVIEW_EVENT_LIMIT).forEachIndexed { index, event ->
                if (index > 0) append('\n')
                append(previewEventJson(event, request))
            }
            if (events.size > PREVIEW_EVENT_LIMIT) {
                append("\n… ").append(events.size - PREVIEW_EVENT_LIMIT).append(" more matching records in the saved file.")
            }
        }
        append("\n\nThe JSON file is not encrypted. A destination may sync files to a cloud provider; review the chosen save location.")
        append("\nA hostname or socket-owner label is included only when its corresponding checkbox is selected.")
    }

    private fun eventJson(record: AuditChainRecord): String = buildString {
        append("{\"timestamp\": ").append(jsonString(record.timestamp))
        append(", \"local_date\": ").append(jsonString(record.localDate))
        append(", \"category\": ").append(jsonString(record.category))
        append(", \"queried_hostname\": ").append(jsonString(record.queriedHostname))
        append(", \"socket_owner_label\": ").append(jsonString(record.socketOwnerLabel))
        append(", \"previous_record_sha256\": ").append(jsonString(record.previousRecordSha256))
        append(", \"record_sha256\": ").append(jsonString(record.recordSha256))
        append('}')
    }

    private fun previewEventJson(event: NormalizedEvent, request: AuditExportRequest): String = buildString {
        append("{\"timestamp\": ").append(jsonString(event.timestamp.toString()))
        append(", \"local_date\": ").append(jsonString(event.localDate.toString()))
        append(", \"category\": ").append(jsonString(event.category))
        append(", \"queried_hostname\": ").append(jsonString(if (request.includeHostnames) event.hostname else "[REDACTED]"))
        append(", \"socket_owner_label\": ").append(jsonString(if (request.includeSocketOwnerLabels) event.socketOwnerLabel else "[REDACTED]"))
        append('}')
    }

    private fun jsonArray(items: List<String>): String =
        items.joinToString(prefix = "[", postfix = "]", separator = ", ")

    private fun jsonString(value: String): String = buildString(value.length + 2) {
        append('"')
        for (character in value) {
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) {
                    append("\\u")
                    append(character.code.toString(16).padStart(4, '0'))
                } else {
                    append(character)
                }
            }
        }
        append('"')
    }
}
