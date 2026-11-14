package org.privacage.android

import com.android.apksig.ApkVerifier
import java.io.File

internal enum class ApkSignatureStatus {
    VERIFIED,
    INVALID,
    ERROR
}

internal data class ApkSignatureVerification(
    val status: ApkSignatureStatus,
    val errors: List<String>,
    val warnings: List<String>
)

/**
 * Cryptographically verifies APK signatures using Google's apksig implementation.
 *
 * VERIFIED means the signature and covered APK content pass apksig's checks for the
 * platform range inferred from the APK manifest. It does not establish publisher identity,
 * app safety, or trustworthiness. An ERROR is distinct from an INVALID signature.
 */
internal object ApkSignatureVerifier {
    fun verify(apkFile: File): ApkSignatureVerification {
        return try {
            val result = ApkVerifier.Builder(apkFile).build().verify()
            ApkSignatureVerification(
                status = if (result.isVerified()) ApkSignatureStatus.VERIFIED else ApkSignatureStatus.INVALID,
                errors = result.errors.map { it.toString() }.take(MAX_ISSUES),
                warnings = result.warnings.map { it.toString() }.take(MAX_ISSUES)
            )
        } catch (exception: Exception) {
            ApkSignatureVerification(
                status = ApkSignatureStatus.ERROR,
                errors = listOf(
                    "${exception.javaClass.simpleName}: ${exception.message ?: "verification could not be completed"}"
                ),
                warnings = emptyList()
            )
        }
    }

    private const val MAX_ISSUES = 20
}
