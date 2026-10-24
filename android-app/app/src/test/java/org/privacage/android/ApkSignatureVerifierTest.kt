package org.privacage.android

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class ApkSignatureVerifierTest {
    @Test
    fun malformedApkIsNeverReportedAsVerified() {
        val apk = Files.createTempFile("privacage-invalid-apk-", ".apk").toFile()
        try {
            apk.writeBytes("not an apk".toByteArray(Charsets.US_ASCII))

            val result = ApkSignatureVerifier.verify(apk)

            assertFalse(result.status == ApkSignatureStatus.VERIFIED)
            assertFalse(result.errors.isEmpty())
        } finally {
            apk.delete()
        }
    }
}
