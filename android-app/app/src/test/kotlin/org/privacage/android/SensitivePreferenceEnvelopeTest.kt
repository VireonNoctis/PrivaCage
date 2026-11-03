package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import javax.crypto.spec.SecretKeySpec

class SensitivePreferenceEnvelopeTest {
    private fun key(seed: Int) =
        SecretKeySpec(ByteArray(32) { (it + seed).toByte() }, "AES")

    @Test
    fun encryptsAndDecryptsWithPurposeBoundAuthentication() {
        val plaintext = """{"private_setting":"kept locally"}"""
        val envelope = SensitivePreferenceEnvelope.encrypt(
            plaintext,
            key(1),
            "rights-request-tracker",
            4096
        )
        assertEquals(
            plaintext,
            SensitivePreferenceEnvelope.decrypt(
                envelope,
                key(1),
                "rights-request-tracker",
                4096
            )
        )
        assertThrows(IOException::class.java) {
            SensitivePreferenceEnvelope.decrypt(envelope, key(2), "rights-request-tracker", 4096)
        }
        assertThrows(IOException::class.java) {
            SensitivePreferenceEnvelope.decrypt(envelope, key(1), "permission-audit-baseline", 4096)
        }
    }

    @Test
    fun rejectsTamperedCiphertextAndUnsupportedEnvelopeFields() {
        val envelope = SensitivePreferenceEnvelope.encrypt(
            """{"schema_version":1}""",
            key(3),
            "dns-configuration",
            4096
        )
        val parsed = org.json.JSONObject(envelope)
        val ciphertext = parsed.getString("ciphertext")
        val tampered = org.json.JSONObject(envelope)
            .put("ciphertext", ciphertext.dropLast(2) + if (ciphertext.endsWith("AA")) "BB" else "AA")
            .toString()
        assertThrows(IOException::class.java) {
            SensitivePreferenceEnvelope.decrypt(tampered, key(3), "dns-configuration", 4096)
        }
        assertThrows(IOException::class.java) {
            SensitivePreferenceEnvelope.decrypt(
                org.json.JSONObject(envelope).put("unexpected", true).toString(),
                key(3),
                "dns-configuration",
                4096
            )
        }
    }

    @Test
    fun rejectsOversizedAndInvalidPlaintextBeforeEncryption() {
        assertThrows(IOException::class.java) {
            SensitivePreferenceEnvelope.encrypt(
                "x".repeat(4097),
                key(4),
                "dns-configuration",
                4096
            )
        }
        val exception = assertThrows(IllegalArgumentException::class.java) {
            SensitivePreferenceEnvelope.encrypt("value", key(4), "bad label", 4096)
        }
        assertTrue(exception.message.orEmpty().contains("label"))
    }
}
