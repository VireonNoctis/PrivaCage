package org.privacage.android

import org.privacage.audit.AsciiMultiPatternMatcher
import org.privacage.audit.AsciiSearchPattern
import java.io.File
import java.io.IOException
import java.util.LinkedHashSet
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

internal data class ApkTrackerIndicatorFinding(
    val recordId: String,
    val recordName: String,
    val category: String,
    val status: String,
    val confidence: String,
    val indicatorType: String,
    val indicator: String,
    val dexEntries: List<String>,
    val evidenceUrls: List<String>
)

internal data class ApkTrackerScanReport(
    val indicatorsConsidered: Int,
    val dexFilesScanned: Int,
    val dexBytesScanned: Long,
    val findings: List<ApkTrackerIndicatorFinding>,
    val warnings: List<String>
)

/**
 * Searches DEX byte strings for exact catalog literals. A hit is an embedded-string indicator,
 * not proof a class is loaded, a hostname is contacted, or any data is transmitted.
 *
 * All work is local. Limits bound decompression and matching work for user-selected APK archives.
 */
internal class ApkTrackerIndicatorScanner {
    private data class Marker(
        val key: String,
        val record: TrackerSignature,
        val kind: String,
        val value: String
    )

    fun scan(apkFile: File, signatures: List<TrackerSignature>): ApkTrackerScanReport {
        if (!apkFile.isFile || apkFile.length() !in 1..MAX_APK_ARCHIVE_BYTES) {
            throw IOException("APK archive must be a readable file no larger than 100 MiB.")
        }
        val warnings = LinkedHashSet<String>()
        val markers = linkedMapOf<String, Marker>()
        val patterns = mutableListOf<AsciiSearchPattern>()
        var markerCapReported = false
        var unsupportedReported = false
        var wildcardReported = false

        fun register(record: TrackerSignature, kind: String, value: String, forms: List<String>) {
            if (markers.size >= MAX_TRACKER_MARKERS) {
                if (!markerCapReported) {
                    warnings += "Tracker scan limited to the first " + MAX_TRACKER_MARKERS + " catalog indicators."
                    markerCapReported = true
                }
                return
            }
            val acceptedForms = forms.distinct().filter { form ->
                form.isNotEmpty() && form.all { it.code in 0x20..0x7e } &&
                    !form.contains('*') && !form.contains('?')
            }
            if (acceptedForms.isEmpty()) {
                if (!unsupportedReported) {
                    warnings += "One or more non-ASCII, wildcard, or empty SDK indicators were skipped because only literal ASCII strings are supported."
                    unsupportedReported = true
                }
                return
            }
            val key = "marker-" + markers.size
            markers[key] = Marker(key, record, kind, value)
            acceptedForms.forEach { patterns += AsciiSearchPattern(key, it) }
        }

        signatures.sortedBy { it.id }.forEach { record ->
            record.domains.forEach { domain -> register(record, "domain", domain, listOf(domain)) }
            record.sdkPatterns.forEach { sdkPattern ->
                when {
                    sdkPattern.endsWith(".**") || sdkPattern.endsWith(".*") -> {
                        val prefix = sdkPattern.removeSuffix("**").removeSuffix("*")
                        register(record, "SDK package prefix", sdkPattern, listOf(prefix, prefix.replace('.', '/')))
                    }
                    sdkPattern.contains('*') || sdkPattern.contains('?') -> {
                        if (!wildcardReported) {
                            warnings += "Unsupported SDK wildcard placement was skipped; only literal names and terminal .* or .** package prefixes are supported."
                            wildcardReported = true
                        }
                    }
                    else -> register(record, "SDK pattern", sdkPattern, listOf(sdkPattern, sdkPattern.replace('.', '/')))
                }
            }
        }

        if (patterns.isEmpty()) {
            warnings += "The bundled catalog did not provide any scanable literal indicators."
            return ApkTrackerScanReport(0, 0, 0L, emptyList(), warnings.toList())
        }

        val hitsByMarker = linkedMapOf<String, MutableSet<String>>()
        var dexFilesScanned = 0
        var dexBytesScanned = 0L
        val dexEntries = mutableListOf<ZipEntry>()

        ZipFile(apkFile).use { zip ->
            val entries = zip.entries()
            var entriesExamined = 0
            var archiveEntryLimitReached = false
            while (entries.hasMoreElements()) {
                if (entriesExamined >= MAX_ARCHIVE_ENTRIES) {
                    archiveEntryLimitReached = true
                    break
                }
                val entry = entries.nextElement()
                entriesExamined++
                if (entry.isDirectory || !entry.name.endsWith(".dex", ignoreCase = true)) continue
                if (dexEntries.size >= MAX_DEX_FILES) {
                    warnings += "More than " + MAX_DEX_FILES + " DEX files exist; additional DEX files were not scanned."
                    break
                }
                dexEntries += entry
            }
            if (archiveEntryLimitReached) {
                warnings += "ZIP entry scan reached the " + MAX_ARCHIVE_ENTRIES + "-entry limit."
            }
            if (dexEntries.isEmpty()) {
                warnings += "No DEX entries were found; bytecode string scanning did not run."
            }

            val matcher = AsciiMultiPatternMatcher(patterns)
            for (entry in dexEntries) {
                val remainingTotalBudget = MAX_TOTAL_DEX_BYTES - dexBytesScanned
                if (entry.size < 0L || entry.compressedSize < 0L) {
                    warnings += "Skipped " + entry.name + ": ZIP entry sizes are unavailable."
                    continue
                }
                if (exceedsExpansionRatio(entry.size, entry.compressedSize)) {
                    warnings += "Skipped " + entry.name + ": expansion ratio exceeds " +
                        MAX_ENTRY_EXPANSION_RATIO + ":1."
                    continue
                }
                if (entry.size > MAX_DEX_ENTRY_BYTES || entry.size > remainingTotalBudget) {
                    warnings += "Skipped " + entry.name + ": its declared uncompressed size exceeds the remaining DEX scan budget."
                    continue
                }
                if (remainingTotalBudget <= 0L) {
                    warnings += "DEX scan stopped at the " + MAX_TOTAL_DEX_BYTES + "-byte total decompression limit."
                    break
                }

                matcher.reset()
                val entryHits = LinkedHashSet<String>()
                val buffer = ByteArray(READ_BUFFER_BYTES)
                var entryBytes = 0L
                var limitReached = false
                try {
                    zip.getInputStream(entry).use { input ->
                        while (true) {
                            val budget = minOf(MAX_DEX_ENTRY_BYTES - entryBytes, MAX_TOTAL_DEX_BYTES - dexBytesScanned)
                            if (budget <= 0L) {
                                limitReached = true
                                break
                            }
                            val count = input.read(buffer, 0, minOf(buffer.size.toLong(), budget).toInt())
                            if (count < 0) break
                            if (count == 0) continue
                            entryBytes += count
                            dexBytesScanned += count
                            entryHits += matcher.feed(buffer, 0, count)
                        }
                    }
                } finally {
                    buffer.fill(0)
                }
                dexFilesScanned++
                if (entry.size >= 0 && entryBytes != entry.size) {
                    warnings += "DEX entry " + entry.name + " was not fully scanned."
                } else if (entry.size < 0 && limitReached) {
                    warnings += "DEX entry " + entry.name + " reached an inspection limit before end-of-stream."
                } else if (limitReached) {
                    warnings += "DEX scan stopped at an inspection limit."
                }
                for (key in entryHits) hitsByMarker.getOrPut(key) { linkedSetOf() }.add(entry.name)
            }
        }

        val findings = markers.values.mapNotNull { marker ->
            val dexPaths = hitsByMarker[marker.key]?.toList()?.sorted() ?: return@mapNotNull null
            ApkTrackerIndicatorFinding(
                recordId = marker.record.id,
                recordName = marker.record.name,
                category = marker.record.category,
                status = marker.record.status,
                confidence = marker.record.confidence,
                indicatorType = marker.kind,
                indicator = marker.value,
                dexEntries = dexPaths,
                evidenceUrls = marker.record.evidence.map { it.url }
            )
        }.sortedWith(compareBy<ApkTrackerIndicatorFinding> { it.status != "active" }
            .thenBy { it.recordName }
            .thenBy { it.indicatorType }
            .thenBy { it.indicator })

        return ApkTrackerScanReport(
            indicatorsConsidered = markers.size,
            dexFilesScanned = dexFilesScanned,
            dexBytesScanned = dexBytesScanned,
            findings = findings,
            warnings = warnings.toList()
        )
    }

    private fun exceedsExpansionRatio(uncompressedBytes: Long, compressedBytes: Long): Boolean {
        if (uncompressedBytes < MIN_ENTRY_SIZE_FOR_RATIO_CHECK) return false
        if (compressedBytes <= 0L) return true
        val quotient = uncompressedBytes / compressedBytes
        val remainder = uncompressedBytes % compressedBytes
        return quotient > MAX_ENTRY_EXPANSION_RATIO ||
            (quotient == MAX_ENTRY_EXPANSION_RATIO && remainder > 0L)
    }

    companion object {
        private const val MAX_APK_ARCHIVE_BYTES = 100L * 1024 * 1024
        private const val MAX_TRACKER_MARKERS = 4_096
        private const val MAX_ARCHIVE_ENTRIES = 10_000
        private const val MAX_DEX_FILES = 32
        private const val MAX_DEX_ENTRY_BYTES = 32L * 1024 * 1024
        private const val MAX_TOTAL_DEX_BYTES = 64L * 1024 * 1024
        private const val MAX_ENTRY_EXPANSION_RATIO = 200L
        private const val MIN_ENTRY_SIZE_FOR_RATIO_CHECK = 1024L * 1024L
        private const val READ_BUFFER_BYTES = 64 * 1024
    }
}
