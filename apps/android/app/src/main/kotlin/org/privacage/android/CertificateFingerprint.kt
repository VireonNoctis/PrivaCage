package org.privacage.android

import java.security.MessageDigest

/** Stable SHA-256 formatting for APK signer certificate DER bytes. */
internal object CertificateFingerprint {
    fun sha256(certificateBytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(certificateBytes)
        val hexDigits = "0123456789abcdef"
        return buildString(digest.size * 2) {
            for (byte in digest) {
                val value = byte.toInt() and 0xff
                append(hexDigits[value ushr 4])
                append(hexDigits[value and 0x0f])
            }
        }
    }
}
