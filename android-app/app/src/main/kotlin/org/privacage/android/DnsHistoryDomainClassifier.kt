package org.privacage.android

import java.net.IDN
import java.util.Locale

internal data class DnsDomainIndicatorMatch(
    val recordId: String,
    val recordName: String,
    val category: String,
    val status: String,
    val confidence: String,
    val matchedDomain: String,
    val lastVerified: String,
    val evidenceUrl: String?
)

internal data class DnsHistoryDomainClassification(
    val normalizedHostname: String?,
    val catalogAvailable: Boolean,
    val matches: List<DnsDomainIndicatorMatch>
) {
    fun summary(maxMatches: Int = 3): String {
        require(maxMatches >= 1) { "At least one match must be allowed in the summary." }
        if (normalizedHostname == null) {
            return "Catalogue lookup skipped: the recorded value is not a valid DNS hostname."
        }
        if (!catalogAvailable) {
            return "Catalogue lookup unavailable: the bundled tracker catalogue has not loaded successfully."
        }
        if (matches.isEmpty()) {
            return "Catalogue: no bundled domain indicator matched. This does not prove the destination is harmless or that no tracking occurred."
        }

        return buildString {
            appendLine("Catalogue indicators (endpoint evidence, not a runtime verdict):")
            matches.take(maxMatches).forEach { match ->
                val statusLabel = when (match.status) {
                    "active" -> "active indicator"
                    "review" -> "review-only indicator"
                    "retired" -> "retired indicator"
                    else -> "unclassified indicator"
                }
                append("- ")
                append(match.recordName)
                append(" [").append(statusLabel).append("; ").append(match.confidence).append(" confidence]")
                append("; matched domain: ").append(match.matchedDomain)
                append("; last verified: ").append(match.lastVerified)
                match.evidenceUrl?.let { append("; evidence: ").append(it) }
                appendLine()
            }
            if (matches.size > maxMatches) {
                appendLine("Additional catalogue matches omitted from this view: ").append(matches.size - maxMatches)
            }
            append("A domain match does not identify the initiating app or prove what data was sent.")
        }
    }
}

/**
 * Adds evidence-backed context to an observed DNS hostname without changing blocking rules.
 *
 * Only catalogue domain indicators are considered. SDK class-name signatures are irrelevant to
 * DNS history. Matching is label-boundary-aware so "tracker.example.attacker.invalid" cannot
 * match "tracker.example". A match identifies a catalogued endpoint, not a confirmed data flow.
 */
internal object DnsHistoryDomainClassifier {
    private val allowedStatuses = setOf("active", "review", "retired")
    private val labelPattern = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

    fun classify(
        hostname: String,
        catalog: List<TrackerSignature>?
    ): DnsHistoryDomainClassification {
        val normalizedHostname = normalizeHostname(hostname)
            ?: return DnsHistoryDomainClassification(
                normalizedHostname = null,
                catalogAvailable = catalog != null,
                matches = emptyList()
            )
        if (catalog == null) {
            return DnsHistoryDomainClassification(
                normalizedHostname = normalizedHostname,
                catalogAvailable = false,
                matches = emptyList()
            )
        }

        val candidates = catalog.asSequence()
            .filter { it.status in allowedStatuses }
            .flatMap { record ->
                record.domains.asSequence().mapNotNull { rawDomain ->
                    val domain = normalizeHostname(rawDomain) ?: return@mapNotNull null
                    if (normalizedHostname != domain && !normalizedHostname.endsWith(".$domain")) {
                        return@mapNotNull null
                    }
                    DnsDomainIndicatorMatch(
                        recordId = record.id,
                        recordName = record.name,
                        category = record.category,
                        status = record.status,
                        confidence = record.confidence,
                        matchedDomain = domain,
                        lastVerified = record.lastVerified,
                        evidenceUrl = record.evidence.firstOrNull()?.url
                    )
                }
            }
            // One record can include both a parent and a more-specific hostname. Show only its
            // most-specific matching domain so the same indicator isn't repeated in the UI.
            .groupBy { it.recordId }
            .values
            .mapNotNull { sameRecord -> sameRecord.maxByOrNull { it.matchedDomain.length } }
            .sortedWith(
                compareBy<DnsDomainIndicatorMatch> { statusRank(it.status) }
                    .thenBy { confidenceRank(it.confidence) }
                    .thenBy { it.recordName.lowercase(Locale.ROOT) }
            )
            .toList()

        return DnsHistoryDomainClassification(
            normalizedHostname = normalizedHostname,
            catalogAvailable = true,
            matches = candidates
        )
    }

    private fun normalizeHostname(value: String): String? {
        if (value.isEmpty() || value != value.trim() || value.length > 1024) return null
        val withoutRootDot = value.removeSuffix(".")
        if (withoutRootDot.isEmpty() || withoutRootDot.endsWith(".")) return null

        val ascii = try {
            IDN.toASCII(withoutRootDot, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (ascii.length !in 1..253) return null
        val labels = ascii.split('.')
        if (labels.any { it.length !in 1..63 || !labelPattern.matches(it) }) return null
        return ascii
    }

    private fun statusRank(status: String): Int = when (status) {
        "active" -> 0
        "review" -> 1
        "retired" -> 2
        else -> 3
    }

    private fun confidenceRank(confidence: String): Int = when (confidence) {
        "high" -> 0
        "medium" -> 1
        "low" -> 2
        else -> 3
    }
}
