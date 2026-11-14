package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject
import java.io.IOException
import java.util.Base64
import javax.crypto.spec.SecretKeySpec

class AndroidSensitivePreferenceVaultTest {
    private val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")

    @Test
    fun authenticExistingEnvelopeIsDecryptedAndSchemaValidatedBeforeReplacement() {
        val plaintext = """{"schema_version":1,"value":"preserve"}"""
        val envelope = SensitivePreferenceEnvelope.encrypt(
            plaintext,
            key,
            AAD_LABEL,
            MAX_BYTES
        )
        var validationCalls = 0

        AndroidSensitivePreferenceVault.validateExistingEncryptedValue(
            envelope,
            key,
            AAD_LABEL,
            MAX_BYTES
        ) { existing ->
            validationCalls += 1
            assertEquals(plaintext, existing)
        }

        assertEquals(1, validationCalls)
    }

    @Test
    fun tamperedExistingEnvelopeFailsAuthenticationBeforeSchemaValidation() {
        val validEnvelope = JSONObject(
            SensitivePreferenceEnvelope.encrypt(
                """{"schema_version":1}""",
                key,
                AAD_LABEL,
                MAX_BYTES
            )
        )
        val ciphertext = Base64.getDecoder().decode(validEnvelope.getString("ciphertext"))
        ciphertext[ciphertext.lastIndex] = (ciphertext.last().toInt() xor 1).toByte()
        val tamperedEnvelope = validEnvelope
            .put("ciphertext", Base64.getEncoder().encodeToString(ciphertext))
            .toString()
        var validationCalled = false

        val failure = assertThrows(IOException::class.java) {
            AndroidSensitivePreferenceVault.validateExistingEncryptedValue(
                tamperedEnvelope,
                key,
                AAD_LABEL,
                MAX_BYTES
            ) { validationCalled = true }
        }

        assertFalse(validationCalled)
        assertTrue(failure.message.orEmpty().contains("preserved"))
        assertTrue(tamperedEnvelope.isNotEmpty())
    }

    @Test
    fun authenticatedButInvalidStoredSchemaBlocksReplacement() {
        val oldEnvelope = SensitivePreferenceEnvelope.encrypt(
            """{"schema_version":99}""",
            key,
            AAD_LABEL,
            MAX_BYTES
        )
        val cause = IllegalArgumentException("unsupported schema")

        val failure = assertThrows(IOException::class.java) {
            AndroidSensitivePreferenceVault.validateExistingEncryptedValue(
                oldEnvelope,
                key,
                AAD_LABEL,
                MAX_BYTES
            ) { throw cause }
        }

        assertSame(cause, failure.cause)
        assertTrue(failure.message.orEmpty().contains("preserved"))
    }

    @Test
    fun existingEnvelopeCannotBeValidatedUnderAnotherPurposeLabel() {
        val oldEnvelope = SensitivePreferenceEnvelope.encrypt(
            """{"schema_version":1}""",
            key,
            "rights-request-tracker",
            MAX_BYTES
        )

        assertThrows(IOException::class.java) {
            AndroidSensitivePreferenceVault.validateExistingEncryptedValue(
                oldEnvelope,
                key,
                AAD_LABEL,
                MAX_BYTES
            ) { }
        }
    }

    private companion object {
        const val AAD_LABEL = "permission-audit-baseline"
        const val MAX_BYTES = 4096
    }
}
