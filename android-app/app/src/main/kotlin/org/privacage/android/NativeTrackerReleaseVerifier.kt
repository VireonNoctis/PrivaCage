package org.privacage.android

import android.content.Context
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.time.LocalDate
import java.time.ZoneOffset

internal data class VerifiedTrackerRelease(
    val sequence: Long,
    val catalogSha256: String,
    val manifestSha256: String,
    val createdAt: String,
    val expiresAt: String
)

/**
 * Verifies the exact bundled catalog bytes before the Kotlin catalog parser may use them.
 * The trusted Ed25519 key is pinned in the native library, not read from a replaceable asset.
 */
internal object NativeTrackerReleaseVerifier {
    private const val LIBRARY_NAME = "pcage_tracker_release_jni"
    private const val MANIFEST_ASSET_NAME = "signatures.manifest.json"
    internal const val MAX_CATALOG_BYTES = 5 * 1024 * 1024
    private const val MAX_MANIFEST_BYTES = 16 * 1024
    private val digestPattern = Regex("^[0-9a-f]{64}$")
    private val loadFailure: UnsatisfiedLinkError? = try {
        System.loadLibrary(LIBRARY_NAME)
        null
    } catch (error: UnsatisfiedLinkError) {
        error
    }

    fun verify(context: Context, catalogBytes: ByteArray): VerifiedTrackerRelease {
        if (catalogBytes.isEmpty() || catalogBytes.size > MAX_CATALOG_BYTES) {
            throw IOException("Tracker catalog exceeds the supported size limit")
        }
        loadFailure?.let {
            throw IOException("Tracker release verification is unavailable; the catalog has been locked.", it)
        }

        val manifestBytes = readBoundedAsset(context, MANIFEST_ASSET_NAME, MAX_MANIFEST_BYTES)
        val asOf = LocalDate.now(ZoneOffset.UTC).toString()
        val rawResponse = try {
            nativeVerifyCatalog(catalogBytes, manifestBytes, asOf)
        } catch (error: UnsatisfiedLinkError) {
            throw IOException("Tracker release verification failed because the native verifier is unavailable.", error)
        }
        val response = try {
            JSONObject(rawResponse)
        } catch (exception: Exception) {
            throw IOException("Tracker release verifier returned an invalid response.", exception)
        }
        if (!response.optBoolean("ok", false)) {
            val reason = response.optString("error", "Unspecified verification failure")
            throw IOException("Tracker release verification failed: $reason")
        }

        val sequence = response.optLong("sequence", 0L)
        val catalogSha256 = response.optString("catalog_sha256", "")
        val manifestSha256 = response.optString("manifest_sha256", "")
        val createdAt = response.optString("created_at", "")
        val expiresAt = response.optString("expires_at", "")
        if (sequence < 1L || !digestPattern.matches(catalogSha256) || !digestPattern.matches(manifestSha256)) {
            throw IOException("Tracker release verifier returned malformed release metadata.")
        }
        return VerifiedTrackerRelease(sequence, catalogSha256, manifestSha256, createdAt, expiresAt)
    }

    internal fun readBoundedAsset(context: Context, name: String, maxBytes: Int): ByteArray {
        return readBounded(context.assets.open(name), name, maxBytes)
    }

    private fun readBounded(input: InputStream, name: String, maxBytes: Int): ByteArray {
        input.use { stream ->
            val output = ByteArrayOutputStream(minOf(maxBytes, 8192))
            val buffer = ByteArray(4096)
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                if (output.size().toLong() + count > maxBytes.toLong()) {
                    throw IOException("$name exceeds the $maxBytes-byte size limit")
                }
                output.write(buffer, 0, count)
            }
            return output.toByteArray()
        }
    }

    private external fun nativeVerifyCatalog(
        catalogBytes: ByteArray,
        manifestBytes: ByteArray,
        asOfUtcDate: String
    ): String
}
