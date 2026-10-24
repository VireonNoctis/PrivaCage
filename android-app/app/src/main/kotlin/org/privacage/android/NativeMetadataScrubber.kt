package org.privacage.android

import org.json.JSONArray
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

    private fun decode(value: String): NativeMetadataReport {
        val response = try {
            JSONObject(value)
        } catch (exception: Exception) {
            throw IOException("Native metadata library returned an invalid response.", exception)
        }
        if (!response.optBoolean("ok", false)) {
            throw IOException(response.optString("error", "Metadata operation failed."))
        }
        val report = response.optJSONObject("report")
            ?: throw IOException("Native metadata library omitted the report.")
        val warningArray = report.optJSONArray("warnings") ?: JSONArray()
        val warnings = List(warningArray.length()) { index ->
            warningArray.optString(index, "Unspecified format limitation.")
        }
        return NativeMetadataReport(
            format = report.getString("format"),
            inputBytes = report.getLong("input_bytes"),
            outputBytes = report.getLong("output_bytes"),
            metadataSegmentsRemoved = report.getLong("metadata_segments_removed"),
            metadataBytesRemoved = report.getLong("metadata_bytes_removed"),
            jpegApp1SegmentsRemoved = report.getLong("jpeg_app1_segments_removed"),
            jpegApp13SegmentsRemoved = report.getLong("jpeg_app13_segments_removed"),
            jpegCommentSegmentsRemoved = report.getLong("jpeg_comment_segments_removed"),
            pngExifChunksRemoved = report.getLong("png_exif_chunks_removed"),
            pngTextChunksRemoved = report.getLong("png_text_chunks_removed"),
            pngTimestampChunksRemoved = report.getLong("png_timestamp_chunks_removed"),
            pngPhysicalChunksRemoved = report.getLong("png_physical_chunks_removed"),
            webpExifChunksRemoved = report.getLong("webp_exif_chunks_removed"),
            webpXmpChunksRemoved = report.getLong("webp_xmp_chunks_removed"),
            warnings = warnings
        )
    }

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
