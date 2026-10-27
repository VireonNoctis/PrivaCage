package org.privacage.android

import org.json.JSONArray
import java.nio.charset.StandardCharsets
import org.json.JSONObject
import java.io.File
import java.io.IOException

internal data class NativeMetadataReport(
    val format: String,
    val inputBytes: Long,
    val outputBytes: Long,
    val metadataSegmentsRemoved: Long,
    val metadataBytesRemoved: Long,
    val jpegApp1SegmentsRemoved: Long,
    val jpegApp13SegmentsRemoved: Long,
    val jpegCommentSegmentsRemoved: Long,
    val pngExifChunksRemoved: Long,
    val pngTextChunksRemoved: Long,
    val pngTimestampChunksRemoved: Long,
    val pngPhysicalChunksRemoved: Long,
    val webpExifChunksRemoved: Long,
    val webpXmpChunksRemoved: Long,
    val warnings: List<String>
) {
    fun removedSummary(): String = buildString {
        append("Recognized metadata entries removed: ").append(metadataSegmentsRemoved)
            .append(" (").append(metadataBytesRemoved).append(" bytes).")
        when (format) {
            "jpeg" -> {
                append("\nJPEG APP1 / EXIF-XMP-class segments: ").append(jpegApp1SegmentsRemoved)
                append("\nJPEG APP13 / IPTC-Photoshop segments: ").append(jpegApp13SegmentsRemoved)
                append("\nJPEG comments: ").append(jpegCommentSegmentsRemoved)
            }
            "png" -> {
                append("\nPNG EXIF chunks: ").append(pngExifChunksRemoved)
                append("\nPNG text/XMP chunks: ").append(pngTextChunksRemoved)
                append("\nPNG timestamps: ").append(pngTimestampChunksRemoved)
                append("\nPNG physical-resolution chunks: ").append(pngPhysicalChunksRemoved)
            }
            "webp" -> {
                append("\nWebP EXIF chunks: ").append(webpExifChunksRemoved)
                append("\nWebP XMP chunks: ").append(webpXmpChunksRemoved)
            }
        }
    }
}

internal class NativeMetadataScrubber {
    init {
        try {
            System.loadLibrary("pcage_metadata_jni")
        } catch (error: UnsatisfiedLinkError) {
            throw IllegalStateException(
                "The PrivaCage metadata native library is missing. Rebuild the Rust metadata JNI library before using this feature.",
                error
            )
        }
    }

    fun inspect(input: File, maxBytes: Long = DEFAULT_MAX_BYTES): NativeMetadataReport =
        decode(nativeInspectFile(input.absolutePath, maxBytes))

    fun scrub(input: File, output: File, maxBytes: Long = DEFAULT_MAX_BYTES): NativeMetadataReport =
        decode(nativeScrubFile(input.absolutePath, output.absolutePath, maxBytes))

    private fun decode(value: String): NativeMetadataReport =
        decodeNativeMetadataResponse(value)

    private external fun nativeInspectFile(inputPath: String, maxBytes: Long): String

    private external fun nativeScrubFile(
        inputPath: String,
        outputPath: String,
        maxBytes: Long
    ): String

    companion object {
        const val DEFAULT_MAX_BYTES = 100L * 1024 * 1024
    }
}

/**
 * Parses only the documented JNI response schema. Native JSON is still treated as an
 * untrusted boundary: duplicate keys, coercible primitive types, unknown fields, and oversized
 * responses must not become a misleading metadata-removal report.
 */
internal fun decodeNativeMetadataResponse(value: String): NativeMetadataReport {
    if (
        value.length > MAX_NATIVE_RESPONSE_BYTES ||
        value.toByteArray(StandardCharsets.UTF_8).size > MAX_NATIVE_RESPONSE_BYTES
    ) {
        throw IOException("Native metadata library response exceeds the 64 KiB limit.")
    }
    StrictJsonKeyScanner.validate(value, "Native metadata response")
    val response = try {
        JSONObject(value)
    } catch (exception: Exception) {
        throw IOException("Native metadata library returned an invalid response.", exception)
    }

    val ok = response.opt("ok") as? Boolean
        ?: throw IOException("Native metadata library response omitted a JSON boolean 'ok' field.")
    if (!ok) {
        if (jsonObjectKeys(response) != setOf("ok", "error")) {
            throw IOException("Native metadata error response contains missing or unsupported fields.")
        }
        val error = response.opt("error") as? String
        if (error.isNullOrBlank()) throw IOException("Native metadata operation failed with an invalid error message.")
        throw IOException(error)
    }
    if (jsonObjectKeys(response) != setOf("ok", "report")) {
        throw IOException("Native metadata success response contains missing or unsupported fields.")
    }

    val report = response.optJSONObject("report")
        ?: throw IOException("Native metadata library omitted the report.")
    val expectedReportKeys = setOf(
        "format",
        "input_bytes",
        "output_bytes",
        "metadata_segments_removed",
        "metadata_bytes_removed",
        "jpeg_app1_segments_removed",
        "jpeg_app13_segments_removed",
        "jpeg_comment_segments_removed",
        "png_exif_chunks_removed",
        "png_text_chunks_removed",
        "png_timestamp_chunks_removed",
        "png_physical_chunks_removed",
        "webp_exif_chunks_removed",
        "webp_xmp_chunks_removed",
        "warnings"
    )
    if (jsonObjectKeys(report) != expectedReportKeys) {
        throw IOException("Native metadata report contains missing or unsupported fields.")
    }
    val format = report.opt("format") as? String
        ?: throw IOException("Native metadata report format must be text.")
    if (format !in setOf("jpeg", "png", "webp")) {
        throw IOException("Native metadata report format is unsupported.")
    }
    fun count(name: String): Long {
        val raw = report.opt(name)
        val parsed = when (raw) {
            is Int -> raw.toLong()
            is Long -> raw
            else -> throw IOException("Native metadata report field '$name' must be an integer JSON number.")
        }
        if (parsed < 0L) throw IOException("Native metadata report field '$name' cannot be negative.")
        return parsed
    }

    val warningArray = report.opt("warnings") as? JSONArray
        ?: throw IOException("Native metadata report warnings must be an array.")
    if (warningArray.length() > MAX_NATIVE_WARNING_COUNT) {
        throw IOException("Native metadata report contains too many warning entries.")
    }
    val warnings = List(warningArray.length()) { index ->
        val warning = warningArray.opt(index) as? String
            ?: throw IOException("Native metadata report warning $index must be text.")
        if (warning.length > MAX_NATIVE_WARNING_LENGTH) {
            throw IOException("Native metadata report warning $index exceeds the supported length.")
        }
        warning
    }

    val inputBytes = count("input_bytes")
    val outputBytes = count("output_bytes")
    val metadataBytesRemoved = count("metadata_bytes_removed")
    if (outputBytes > inputBytes || metadataBytesRemoved > inputBytes) {
        throw IOException("Native metadata report byte counts exceed the input size.")
    }
    val metadataSegmentsRemoved = count("metadata_segments_removed")
    val categoryCounts = listOf(
        count("jpeg_app1_segments_removed"),
        count("jpeg_app13_segments_removed"),
        count("jpeg_comment_segments_removed"),
        count("png_exif_chunks_removed"),
        count("png_text_chunks_removed"),
        count("png_timestamp_chunks_removed"),
        count("png_physical_chunks_removed"),
        count("webp_exif_chunks_removed"),
        count("webp_xmp_chunks_removed")
    )
    if (categoryCounts.sum() > metadataSegmentsRemoved) {
        throw IOException("Native metadata category counters exceed the aggregate segment count.")
    }

    return NativeMetadataReport(
        format = format,
        inputBytes = inputBytes,
        outputBytes = outputBytes,
        metadataSegmentsRemoved = metadataSegmentsRemoved,
        metadataBytesRemoved = metadataBytesRemoved,
        jpegApp1SegmentsRemoved = categoryCounts[0],
        jpegApp13SegmentsRemoved = categoryCounts[1],
        jpegCommentSegmentsRemoved = categoryCounts[2],
        pngExifChunksRemoved = categoryCounts[3],
        pngTextChunksRemoved = categoryCounts[4],
        pngTimestampChunksRemoved = categoryCounts[5],
        pngPhysicalChunksRemoved = categoryCounts[6],
        webpExifChunksRemoved = categoryCounts[7],
        webpXmpChunksRemoved = categoryCounts[8],
        warnings = warnings
    )
}

private fun jsonObjectKeys(value: JSONObject): Set<String> {
    val keys = mutableSetOf<String>()
    val iterator = value.keys()
    while (iterator.hasNext()) keys += iterator.next()
    return keys
}

private const val MAX_NATIVE_RESPONSE_BYTES = 64 * 1024
private const val MAX_NATIVE_WARNING_COUNT = 128
private const val MAX_NATIVE_WARNING_LENGTH = 4_096
