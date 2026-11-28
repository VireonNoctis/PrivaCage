package org.privacage.android

/**
 * Searches every reviewer-facing field in the bundled tracker catalogue.
 *
 * It filters local data only; it does not query DNS, fetch URLs, or modify rules.
 */
internal object TrackerCatalogSearch {
    fun filter(records: List<TrackerSignature>, query: String): List<TrackerSignature> {
        val needle = query.trim()
        if (needle.isEmpty()) return records

        return records.filter { record ->
            val fields = buildList {
                add(record.id)
                add(record.name)
                add(record.category)
                add(record.confidence)
                add(record.status)
                add(record.lastVerified)
                addAll(record.domains)
                addAll(record.sdkPatterns)
                record.evidence.forEach { evidence ->
                    add(evidence.url)
                    add(evidence.description)
                }
            }
            fields.any { it.contains(needle, ignoreCase = true) }
        }
    }
}
