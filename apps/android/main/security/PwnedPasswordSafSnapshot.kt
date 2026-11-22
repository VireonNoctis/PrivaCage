package org.privacage.security

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.time.LocalDate

@Throws(InterruptedIOException::class)
internal fun ensurePwnedPasswordWorkActive() {
    if (Thread.currentThread().isInterrupted) {
        throw InterruptedIOException("Password snapshot work was cancelled.")
    }
}

/**
 * Minimal access surface for a user-selected document provider.
 *
 * The snapshot layer deliberately consumes streams rather than assuming that a
 * provider URI maps to a local filesystem path or a seekable descriptor.
 */
internal interface PwnedPasswordDocumentAccess {
    @Throws(IOException::class)
    fun displayName(uri: String): String?

    @Throws(IOException::class)
    fun open(uri: String): InputStream?
}

/** ContentResolver adapter for SAF document URIs. No storage permission is required. */
internal class AndroidPwnedPasswordDocumentAccess(
    private val resolver: ContentResolver
) : PwnedPasswordDocumentAccess {
    override fun displayName(uri: String): String? {
        val documentUri = parseContentUri(uri)
        val cursor = try {
            resolver.query(
                documentUri,
                arrayOf(OpenableColumns.DISPLAY_NAME),
                null,
                null,
                null
            )
        } catch (exception: SecurityException) {
            throw IOException("Selected document access is unavailable or was revoked.", exception)
        } ?: return null

        return cursor.use {
            val column = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (column < 0 || !it.moveToFirst()) null else it.getString(column)
        }
    }

    override fun open(uri: String): InputStream? {
        return try {
            resolver.openInputStream(parseContentUri(uri))
        } catch (exception: SecurityException) {
            throw IOException("Selected document access is unavailable or was revoked.", exception)
        }
    }

    private fun parseContentUri(value: String): Uri {
        val parsed = try {
            Uri.parse(value)
        } catch (exception: Exception) {
            throw IOException("Selected document URI is invalid.", exception)
        }
        if (parsed.scheme != "content") {
            throw IOException("Only user-selected content:// document URIs are supported.")
        }
        return parsed
    }
}

/**
 * A short-lived private-cache snapshot of one manifest and one selected range.
 *
 * It copies neither the full corpus nor provider metadata such as advertised size.
 * Both streams are bounded while read. The existing manifest/range verifier then
 * authenticates the copied bytes against the separately retained manifest digest
 * and the selected manifest entry.
 *
 * The caller owns this object and must close it when the check screen is left.
 */
internal class PwnedPasswordSafSnapshot private constructor(
    private val snapshotDirectory: Path,
    private val manifestPath: Path,
    private val rangeDirectory: Path,
    val selectedRangePrefix: String,
    private val expectedManifestSha256: String,
    private val expectedRangeCount: Int
) : AutoCloseable {
    private var closed = false

    @Synchronized
    @Throws(IOException::class)
    fun checkAndClear(
        password: CharArray,
        today: LocalDate = LocalDate.now()
    ): PwnedPasswordExposureResult {
        try {
            ensurePwnedPasswordWorkActive()
            if (closed) throw IOException("The selected password dataset snapshot is closed.")
            return PwnedPasswordRangeLookup.checkAndClearWithManifest(
                password = password,
                rangeDirectory = rangeDirectory,
                manifestPath = manifestPath,
                expectedManifestSha256 = expectedManifestSha256,
                today = today,
                expectedRangeCount = expectedRangeCount,
                selectedRangePrefix = selectedRangePrefix
            )
        } finally {
            password.fill('\u0000')
        }
    }

    @Synchronized
    @Throws(IOException::class)
    override fun close() {
        if (closed) return
        cleanupSnapshot(snapshotDirectory, manifestPath, snapshotDirectory.resolve("$selectedRangePrefix.txt"), null)
        closed = true
    }

    internal val snapshotDirectoryForTest: Path
        get() = snapshotDirectory

    companion object {
        private const val TEMP_DIRECTORY_PREFIX = "pcage-pwned-saf-"
        private val rangeFilename = Regex("([0-9A-F]{5})\\.txt")
        private val digestPattern = Regex("[0-9A-Fa-f]{64}")

        /**
         * Snapshots only the user-selected JSONL manifest and one PREFIX.txt file.
         * URI grants are not persisted; the caller must use the active picker grant.
         */
        @Throws(IOException::class)
        fun prepare(
            manifestUri: String,
            expectedManifestSha256: String,
            rangeUri: String,
            documents: PwnedPasswordDocumentAccess,
            cacheDirectory: Path,
            expectedRangeCount: Int = PwnedPasswordManifestVerifier.COMPLETE_RANGE_COUNT
        ): PwnedPasswordSafSnapshot {
            ensurePwnedPasswordWorkActive()
            require(manifestUri.isNotBlank() && rangeUri.isNotBlank()) {
                "Manifest and range document URIs are required."
            }
            require(digestPattern.matches(expectedManifestSha256)) {
                "Expected manifest SHA-256 must contain exactly 64 hexadecimal characters."
            }
            require(expectedRangeCount in 1..PwnedPasswordManifestVerifier.COMPLETE_RANGE_COUNT) {
                "Expected range count is outside the supported prefix space."
            }

            val displayName = documents.displayName(rangeUri)
                ?: throw IOException("The selected range document has no readable display name.")
            ensurePwnedPasswordWorkActive()
            val match = rangeFilename.matchEntire(displayName)
                ?: throw IOException("Select one uppercase five-character PREFIX.txt range document.")
            val prefix = match.groupValues[1]
            if (prefix.toInt(16) >= expectedRangeCount) {
                throw IOException("Selected range prefix is outside the expected manifest inventory.")
            }
            if (!Files.isDirectory(cacheDirectory, LinkOption.NOFOLLOW_LINKS)) {
                throw IOException("The app-private cache directory is unavailable.")
            }

            val directory = Files.createTempDirectory(cacheDirectory, TEMP_DIRECTORY_PREFIX)
            val manifestPath = directory.resolve("manifest.jsonl")
            val rangePath = directory.resolve("$prefix.txt")
            var keepSnapshot = false
            var primaryFailure: Throwable? = null

            try {
                copyBoundedDocument(
                    documents = documents,
                    uri = manifestUri,
                    destination = manifestPath,
                    maximumBytes = PwnedPasswordManifestVerifier.MAX_MANIFEST_BYTES.toLong(),
                    label = "Manifest"
                )
                copyBoundedDocument(
                    documents = documents,
                    uri = rangeUri,
                    destination = rangePath,
                    maximumBytes = PwnedPasswordRangeLookup.MAX_RANGE_FILE_BYTES.toLong(),
                    label = "Selected range"
                )
                val snapshot = PwnedPasswordSafSnapshot(
                    snapshotDirectory = directory,
                    manifestPath = manifestPath,
                    rangeDirectory = directory,
                    selectedRangePrefix = prefix,
                    expectedManifestSha256 = expectedManifestSha256,
                    expectedRangeCount = expectedRangeCount
                )
                keepSnapshot = true
                return snapshot
            } catch (failure: Throwable) {
                primaryFailure = failure
                throw failure
            } finally {
                if (!keepSnapshot) {
                    cleanupSnapshot(directory, manifestPath, rangePath, primaryFailure)
                }
            }
        }

        private fun copyBoundedDocument(
            documents: PwnedPasswordDocumentAccess,
            uri: String,
            destination: Path,
            maximumBytes: Long,
            label: String
        ) {
            ensurePwnedPasswordWorkActive()
            val input = documents.open(uri)
                ?: throw IOException("$label document provider returned no readable stream.")
            input.use { source ->
                ensurePwnedPasswordWorkActive()
                Files.newOutputStream(
                    destination,
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE
                ).use { output ->
                    val buffer = ByteArray(8 * 1024)
                    var totalBytes = 0L
                    try {
                        while (true) {
                            ensurePwnedPasswordWorkActive()
                            val read = source.read(buffer)
                            ensurePwnedPasswordWorkActive()
                            if (read < 0) break
                            if (read == 0) {
                                throw IOException("$label document provider made no read progress.")
                            }
                            if (totalBytes > maximumBytes - read.toLong()) {
                                throw IOException("$label document exceeds its supported byte limit.")
                            }
                            output.write(buffer, 0, read)
                            totalBytes += read.toLong()
                        }
                    } finally {
                        buffer.fill(0)
                    }
                }
            }
        }

        private fun cleanupSnapshot(
            directory: Path,
            manifestPath: Path,
            rangePath: Path,
            primaryFailure: Throwable?
        ) {
            val failures = mutableListOf<Throwable>()
            for (path in listOf(rangePath, manifestPath, directory)) {
                try {
                    Files.deleteIfExists(path)
                } catch (exception: Exception) {
                    failures += exception
                }
            }
            if (failures.isNotEmpty()) {
                val cleanupFailure = IOException("Could not remove the temporary password-dataset snapshot.")
                failures.forEach(cleanupFailure::addSuppressed)
                if (primaryFailure != null) {
                    primaryFailure.addSuppressed(cleanupFailure)
                } else {
                    throw cleanupFailure
                }
            }
        }
    }
}
