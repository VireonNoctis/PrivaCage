package org.privacage.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.privacage.dns.DnsPolicyEngine
import java.io.IOException
import java.net.URI
import java.time.LocalDate
import java.time.format.DateTimeParseException

/** Reads the bundled tracker database; importing a domain is always an explicit user action. */
internal object TrackerSignatureCatalog {
    private const val ASSET_NAME = "signatures.json"
    private const val SUPPORTED_SCHEMA_VERSION = 1
    private const val RELEASE_FLOOR_PREFERENCES = "privacage_tracker_release_floor"
    private const val KEY_ACCEPTED_SEQUENCE = "accepted_sequence"
    private const val KEY_ACCEPTED_MANIFEST_SHA256 = "accepted_manifest_sha256"
    private val topLevelKeys = setOf("schema_version", "updated_at", "entries")
    private val entryKeys = setOf("id", "name", "category", "indicators", "confidence", "status", "last_verified", "evidence")
    private val evidenceKeys = setOf("url", "description")
    private val allowedIndicatorKeys = setOf("domains", "sdk_patterns")
    private val allowedStatuses = setOf("active", "review", "retired")
    private val allowedConfidence = setOf("low", "medium", "high")
    private val sdkPatternRegex = Regex("^[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)+(?:\\.(?:\\*|\\*\\*))?$")

    fun load(context: Context): List<TrackerSignature> {
        val catalogBytes = NativeTrackerReleaseVerifier.readBoundedAsset(context, ASSET_NAME, NativeTrackerReleaseVerifier.MAX_CATALOG_BYTES)
        val verifiedRelease = NativeTrackerReleaseVerifier.verify(context, catalogBytes)
        val releasePreferences = context.getSharedPreferences(RELEASE_FLOOR_PREFERENCES, Context.MODE_PRIVATE)
        val acceptedSequence = releasePreferences.getLong(KEY_ACCEPTED_SEQUENCE, 0L)
        val acceptedManifestSha256 = releasePreferences.getString(KEY_ACCEPTED_MANIFEST_SHA256, null)
        ensureReleaseFloor(verifiedRelease, acceptedSequence, acceptedManifestSha256)
        val text = String(catalogBytes, Charsets.UTF_8)
        val root = try {
            JSONObject(text)
        } catch (exception: Exception) {
            throw IOException("Tracker catalog is not valid JSON", exception)
        }
        requireExactKeys(root, topLevelKeys, "tracker catalog")
        if (!isSupportedSchemaVersion(root.opt("schema_version"))) throw IOException("Unsupported tracker catalog schema version")
        requireDate(root.opt("updated_at"), "updated_at")
        val entries = root.opt("entries") as? JSONArray
            ?: throw IOException("Tracker catalog entries must be an array")
        val seenIds = mutableSetOf<String>()
        val parsedEntries = mutableListOf<TrackerSignature>()

        for (index in 0 until entries.length()) {
            val contextLabel = "entries[$index]"
            val item = entries.optJSONObject(index) ?: throw IOException("$contextLabel must be an object")
            requireExactKeys(item, entryKeys, contextLabel)
            val id = requiredString(item, "id", contextLabel)
            if (!id.matches(Regex("^[a-z0-9]+(?:-[a-z0-9]+)*$"))) throw IOException("$contextLabel.id must be lowercase kebab-case")
            if (!seenIds.add(id)) throw IOException("Duplicate tracker id: $id")

            val name = requiredString(item, "name", contextLabel)
            val category = requiredString(item, "category", contextLabel)
            val confidence = requiredString(item, "confidence", contextLabel)
            if (confidence !in allowedConfidence) throw IOException("$contextLabel has invalid confidence")
            val status = requiredString(item, "status", contextLabel)
            if (status !in allowedStatuses) throw IOException("$contextLabel has invalid status")
            requireDate(item.opt("last_verified"), "$contextLabel.last_verified")

            val indicators = item.optJSONObject("indicators") ?: throw IOException("$contextLabel.indicators must be an object")
            val indicatorKeys = keys(indicators)
            if (indicatorKeys.isEmpty() || !allowedIndicatorKeys.containsAll(indicatorKeys)) {
                throw IOException("$contextLabel.indicators has unsupported or missing indicators")
            }
            val domains = if (indicators.has("domains")) readStringArray(indicators.opt("domains"), "$contextLabel.indicators.domains") else emptyList()
            val sdkPatterns = if (indicators.has("sdk_patterns")) readStringArray(indicators.opt("sdk_patterns"), "$contextLabel.indicators.sdk_patterns") else emptyList()
            if (domains.isEmpty() && sdkPatterns.isEmpty()) throw IOException("$contextLabel has no usable indicators")
            for (pattern in sdkPatterns) {
                if (!sdkPatternRegex.matches(pattern)) throw IOException("$contextLabel contains an unsupported SDK pattern: $pattern")
            }
            for (domain in domains) {
                if (domain != domain.lowercase() || domain.endsWith(".")) throw IOException("$contextLabel has a non-normalized domain: $domain")
            }
            if (domains.isNotEmpty()) {
                try {
                    DnsPolicyEngine(domains.toSet())
                } catch (exception: IllegalArgumentException) {
                    throw IOException("$contextLabel contains an invalid DNS domain", exception)
                }
            }

            val evidenceArray = item.opt("evidence") as? JSONArray ?: throw IOException("$contextLabel.evidence must be an array")
            if (evidenceArray.length() == 0) throw IOException("$contextLabel.evidence must not be empty")
            val evidence = mutableListOf<TrackerEvidence>()
            val seenUrls = mutableSetOf<String>()
            for (evidenceIndex in 0 until evidenceArray.length()) {
                val sourceLabel = "$contextLabel.evidence[$evidenceIndex]"
                val source = evidenceArray.optJSONObject(evidenceIndex) ?: throw IOException("$sourceLabel must be an object")
                requireExactKeys(source, evidenceKeys, sourceLabel)
                val url = requiredString(source, "url", sourceLabel)
                val parsedUrl = try { URI(url) } catch (exception: Exception) {
                    throw IOException("$sourceLabel.url is invalid", exception)
                }
                if (parsedUrl.scheme != "https" || parsedUrl.host.isNullOrBlank() || parsedUrl.rawUserInfo != null) throw IOException("$sourceLabel.url must be an HTTPS URL without credentials")
                if (!seenUrls.add(url)) throw IOException("$sourceLabel contains a duplicate URL")
                evidence += TrackerEvidence(url, requiredString(source, "description", sourceLabel))
            }

            parsedEntries += TrackerSignature(
                id, name, category, domains, sdkPatterns, confidence, status,
                requiredString(item, "last_verified", contextLabel), evidence
            )
        }
        if (verifiedRelease.sequence > acceptedSequence) {
            val stored = releasePreferences.edit()
                .putLong(KEY_ACCEPTED_SEQUENCE, verifiedRelease.sequence)
                .putString(KEY_ACCEPTED_MANIFEST_SHA256, verifiedRelease.manifestSha256)
                .commit()
            if (!stored) throw IOException("Could not persist tracker release rollback protection; catalog remains unavailable")
        }
        return parsedEntries
    }

    internal fun ensureReleaseFloor(
        release: VerifiedTrackerRelease,
        acceptedSequence: Long,
        acceptedManifestSha256: String?
    ) {
        if (acceptedSequence < 0L) throw IOException("Stored tracker release sequence is invalid")
        if (acceptedSequence == 0L && acceptedManifestSha256 != null) {
            throw IOException("Stored tracker release rollback state is inconsistent")
        }
        if (acceptedSequence > 0L && (acceptedManifestSha256 == null || !Regex("^[0-9a-f]{64}$").matches(acceptedManifestSha256))) {
            throw IOException("Stored tracker release rollback state is incomplete or invalid")
        }
        if (release.sequence < acceptedSequence) {
            throw IOException("Tracker release rollback rejected: sequence ${release.sequence} is below the stored sequence ${acceptedSequence}")
        }
        if (release.sequence == acceptedSequence && acceptedSequence > 0L && release.manifestSha256 != acceptedManifestSha256) {
            throw IOException("Tracker release replacement rejected: a sequence cannot identify two different manifests")
        }
    }

    internal fun isSupportedSchemaVersion(value: Any?): Boolean =
        value is Int && value == SUPPORTED_SCHEMA_VERSION

    private fun requireExactKeys(value: JSONObject, expected: Set<String>, context: String) {
        if (keys(value) != expected) throw IOException("$context fields do not match the supported schema")
    }

    private fun keys(value: JSONObject): Set<String> {
        val result = mutableSetOf<String>()
        val iterator = value.keys()
        while (iterator.hasNext()) result += iterator.next()
        return result
    }

    private fun requiredString(value: JSONObject, key: String, context: String): String {
        val result = value.opt(key)
        if (result !is String || result.isBlank() || result != result.trim()) {
            throw IOException("$context.$key must be non-empty trimmed text")
        }
        return result
    }

    private fun requireDate(value: Any?, context: String) {
        if (value !is String) throw IOException("$context must use YYYY-MM-DD format")
        try {
            if (LocalDate.parse(value).toString() != value) {
                throw IOException("$context must use canonical YYYY-MM-DD format")
            }
        } catch (exception: DateTimeParseException) {
            throw IOException("$context must be a valid calendar date in YYYY-MM-DD format", exception)
        }
    }

    private fun readStringArray(value: Any?, context: String): List<String> {
        val array = value as? JSONArray ?: throw IOException("$context must be an array")
        val values = mutableListOf<String>()
        for (index in 0 until array.length()) {
            val item = array.opt(index)
            if (item !is String || item.isBlank() || item != item.trim()) {
                throw IOException("$context[$index] must be non-empty trimmed text")
            }
            values += item
        }
        if (values.size != values.toSet().size) throw IOException("$context contains duplicates")
        return values
    }
}

internal data class TrackerSignature(
    val id: String,
    val name: String,
    val category: String,
    val domains: List<String>,
    val sdkPatterns: List<String>,
    val confidence: String,
    val status: String,
    val lastVerified: String,
    val evidence: List<TrackerEvidence>
)

internal data class TrackerEvidence(val url: String, val description: String)
