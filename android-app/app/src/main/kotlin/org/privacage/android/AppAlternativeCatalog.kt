package org.privacage.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import java.time.LocalDate

internal data class AppAlternativeSource(
    val id: String,
    val label: String,
    val url: String
)

internal data class AppAlternative(
    val id: String,
    val replaces: String,
    val category: String,
    val name: String,
    val summary: String,
    val tradeoffs: String,
    val evidenceUrl: String,
    val sources: List<AppAlternativeSource>
)

/**
 * Reads a reviewed, bundled catalogue of Android app alternatives.
 *
 * This is deliberately a link catalogue, not an APK download/install engine. Only HTTPS links
 * to reviewed hostnames are accepted; package installation and user confirmations remain with
 * Android and the selected official store/source.
 */
internal object AppAlternativeCatalog {
    private const val ASSET_NAME = "catalog.json"
    private const val SUPPORTED_SCHEMA_VERSION = 1
    private const val MAX_CATALOG_BYTES = 512 * 1024
    private val topLevelKeys = setOf("schema_version", "updated_at", "alternatives")
    private val alternativeKeys = setOf(
        "id", "replaces", "category", "name", "summary", "tradeoffs", "evidence_url", "sources"
    )
    private val sourceKeys = setOf("id", "label", "url")
    private val sourceIds = setOf("play", "fdroid", "official", "github", "gitlab")
    private val idPattern = Regex("^[a-z0-9]+(?:-[a-z0-9]+)*$")
    private val approvedHosts = setOf(
        "anysoftkeyboard.github.io",
        "bitwarden.com",
        "brave.com",
        "duckduckgo.com",
        "ente.io",
        "f-droid.org",
        "getaegis.app",
        "github.com",
        "gitlab.com",
        "jitsi.org",
        "joplinapp.org",
        "newpipe.net",
        "nextcloud.com",
        "organicmaps.app",
        "osmand.net",
        "play.google.com",
        "proton.me",
        "signal.org",
        "simplex.chat",
        "support.mozilla.org",
        "www.collaboraoffice.com",
        "www.fossify.org",
        "www.keepassdx.com",
        "www.mozilla.org",
        "www.thunderbird.net"
    )

    fun load(context: Context): List<AppAlternative> {
        val bytes = context.assets.open(ASSET_NAME).use { input ->
            val output = ByteArrayOutputStream(16 * 1024)
            val buffer = ByteArray(4096)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                if (output.size().toLong() + count > MAX_CATALOG_BYTES.toLong()) {
                    throw IOException("Alternative catalogue exceeds the " + MAX_CATALOG_BYTES + "-byte size limit")
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        return parseJson(String(bytes, Charsets.UTF_8))
    }

    internal fun parseJson(document: String): List<AppAlternative> {
        if (document.toByteArray(Charsets.UTF_8).size > MAX_CATALOG_BYTES) {
            throw IOException("Alternative catalogue exceeds the " + MAX_CATALOG_BYTES + "-byte size limit")
        }
        val root = try {
            JSONObject(document)
        } catch (exception: JSONException) {
            throw IOException("Alternative catalogue is not valid JSON", exception)
        }
        requireExactKeys(root, topLevelKeys, "catalogue")
        val schemaVersion = root.opt("schema_version") as? Number
            ?: throw IOException("catalogue.schema_version must be an integer")
        if (schemaVersion.toDouble() != schemaVersion.toInt().toDouble() ||
            schemaVersion.toInt() != SUPPORTED_SCHEMA_VERSION) {
            throw IOException("Unsupported alternative catalogue schema version")
        }
        val updatedAt = requiredString(root, "updated_at", "catalogue")
        try {
            LocalDate.parse(updatedAt)
        } catch (exception: Exception) {
            throw IOException("catalogue.updated_at must be an ISO date (YYYY-MM-DD)", exception)
        }

        val array = root.opt("alternatives") as? JSONArray
            ?: throw IOException("catalogue.alternatives must be an array")
        if (array.length() !in 1..200) {
            throw IOException("catalogue.alternatives must contain between 1 and 200 entries")
        }

        val seenIds = mutableSetOf<String>()
        val output = ArrayList<AppAlternative>(array.length())
        for (index in 0 until array.length()) {
            val contextLabel = "catalogue.alternatives[" + index + "]"
            val item = array.optJSONObject(index) ?: throw IOException(contextLabel + " must be an object")
            requireExactKeys(item, alternativeKeys, contextLabel)
            val id = requiredString(item, "id", contextLabel)
            if (!id.matches(idPattern)) throw IOException(contextLabel + ".id must be lowercase kebab-case")
            if (!seenIds.add(id)) throw IOException("Duplicate alternative id: " + id)

            val replaces = requiredString(item, "replaces", contextLabel, 100)
            val category = requiredString(item, "category", contextLabel, 60)
            val name = requiredString(item, "name", contextLabel, 100)
            val summary = requiredString(item, "summary", contextLabel, 600)
            val tradeoffs = requiredString(item, "tradeoffs", contextLabel, 700)
            val evidenceUrl = requiredString(item, "evidence_url", contextLabel, 2048)
            validateTrustedHttpsUrl(evidenceUrl, contextLabel + ".evidence_url")

            val sourceArray = item.opt("sources") as? JSONArray
                ?: throw IOException(contextLabel + ".sources must be an array")
            if (sourceArray.length() !in 1..4) {
                throw IOException(contextLabel + ".sources must contain between 1 and 4 choices")
            }
            val seenSources = mutableSetOf<String>()
            val sources = ArrayList<AppAlternativeSource>(sourceArray.length())
            for (sourceIndex in 0 until sourceArray.length()) {
                val sourceContext = contextLabel + ".sources[" + sourceIndex + "]"
                val sourceObject = sourceArray.optJSONObject(sourceIndex)
                    ?: throw IOException(sourceContext + " must be an object")
                requireExactKeys(sourceObject, sourceKeys, sourceContext)
                val sourceId = requiredString(sourceObject, "id", sourceContext, 20)
                if (sourceId !in sourceIds) throw IOException(sourceContext + ".id is not a supported source type")
                if (!seenSources.add(sourceId)) throw IOException("Duplicate source type in " + contextLabel + ": " + sourceId)
                val label = requiredString(sourceObject, "label", sourceContext, 80)
                val url = requiredString(sourceObject, "url", sourceContext, 2048)
                validateTrustedHttpsUrl(url, sourceContext + ".url")
                sources += AppAlternativeSource(sourceId, label, url)
            }

            output += AppAlternative(
                id = id,
                replaces = replaces,
                category = category,
                name = name,
                summary = summary,
                tradeoffs = tradeoffs,
                evidenceUrl = evidenceUrl,
                sources = sources
            )
        }
        return output
    }

    private fun requiredString(
        objectValue: JSONObject,
        key: String,
        context: String,
        maxLength: Int = 2048
    ): String {
        val value = objectValue.opt(key) as? String
            ?: throw IOException(context + "." + key + " must be a string")
        if (value.isBlank() || value.length > maxLength || value.any { it == '\u0000' }) {
            throw IOException(context + "." + key + " must be non-empty and no longer than " + maxLength + " characters")
        }
        return value
    }

    private fun requireExactKeys(objectValue: JSONObject, expected: Set<String>, context: String) {
        val actual = mutableSetOf<String>()
        val iterator = objectValue.keys()
        while (iterator.hasNext()) actual += iterator.next()
        if (actual != expected) {
            val missing = (expected - actual).sorted()
            val unknown = (actual - expected).sorted()
            throw IOException(
                context + " has an invalid field set; missing=" + missing.joinToString(",") +
                    "; unknown=" + unknown.joinToString(",")
            )
        }
    }

    private fun validateTrustedHttpsUrl(value: String, context: String) {
        val uri = try {
            URI(value)
        } catch (exception: Exception) {
            throw IOException(context + " is not a valid URL", exception)
        }
        val host = uri.host?.lowercase()
        if (!uri.scheme.equals("https", ignoreCase = true) ||
            host == null ||
            host !in approvedHosts ||
            uri.userInfo != null ||
            uri.port !in setOf(-1, 443) ||
            uri.rawFragment != null ||
            uri.rawPath.isNullOrBlank() ||
            uri.rawPath.contains("\\") ||
            value.any { it.isWhitespace() }) {
            throw IOException(context + " must be an HTTPS URL on a reviewed host")
        }
    }
}
