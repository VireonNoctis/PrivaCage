package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import javax.crypto.spec.SecretKeySpec

class ApiTokenEnvelopeTest {
    private fun key(seed: Int) = SecretKeySpec(ByteArray(32) { (it + seed).toByte() }, "AES")

    @Test
    fun encryptsAndDecryptsCredentialData() {
        val secretRecord = """{"schema_version":1,"credentials":[{"provider":"openai","api_key":"sample-secret-token"}]}"""
        val envelope = ApiTokenEnvelope.encrypt(secretRecord, key(1))

        assertEquals(secretRecord, ApiTokenEnvelope.decrypt(envelope, key(1)))
        assertThrows(java.io.IOException::class.java) {
            ApiTokenEnvelope.decrypt(envelope, key(2))
        }
    }

    @Test
    fun rejectsTamperedEnvelopeAndUnsupportedFields() {
        val envelope = ApiTokenEnvelope.encrypt("""{"credentials":[]}""", key(3))
        val parsed = org.json.JSONObject(envelope)
        val ciphertext = parsed.getString("ciphertext")
        val altered = ciphertext.dropLast(2) + if (ciphertext.endsWith("AA")) "BB" else "AA"
        val tampered = org.json.JSONObject(envelope).put("ciphertext", altered).toString()

        assertThrows(java.io.IOException::class.java) {
            ApiTokenEnvelope.decrypt(tampered, key(3))
        }
        assertThrows(java.io.IOException::class.java) {
            ApiTokenEnvelope.decrypt(org.json.JSONObject(envelope).put("unexpected", true).toString(), key(3))
        }
    }

    @Test
    fun rejectsOversizedPlaintext() {
        assertThrows(java.io.IOException::class.java) {
            ApiTokenEnvelope.encrypt("x".repeat(128 * 1024 + 1), key(4))
        }
    }
}

class ApiCredentialSchemaTest {
    private val credential = StoredApiCredential(
        provider = ApiProvider.OPENAI,
        model = "gpt-4.1-mini",
        apiKey = "test-api-token-value",
        purpose = "Review privacy documents I paste into the app",
        allowedTasks = setOf(
            PrivacyAutomationTask.PRIVACY_POLICY_REVIEW,
            PrivacyAutomationTask.TERMS_REVIEW
        )
    )

    @Test
    fun credentialRecordsRoundTripWithExplicitTaskPermissions() {
        val encoded = ApiTokenVault.encodeCredentials(listOf(credential))
        val decoded = ApiTokenVault.decodeCredentials(encoded)

        assertEquals(credential, decoded[ApiProvider.OPENAI.id])
    }

    @Test
    fun rejectsDuplicateProviderAndInvalidTaskPermissions() {
        assertThrows(IllegalArgumentException::class.java) {
            ApiTokenVault.encodeCredentials(listOf(credential, credential))
        }
        val encoded = ApiTokenVault.encodeCredentials(listOf(credential))
            .replace("terms_review", "unknown_scope")
        assertThrows(java.io.IOException::class.java) {
            ApiTokenVault.decodeCredentials(encoded)
        }
    }

    @Test
    fun rejectsUnscopedOrMalformedCredentials() {
        assertThrows(IllegalArgumentException::class.java) {
            ApiTokenVault.validateCredential(credential.copy(allowedTasks = emptySet()))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ApiTokenVault.validateCredential(credential.copy(apiKey = "token with spaces"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ApiTokenVault.validateCredential(credential.copy(model = "../untrusted"))
        }
    }
}
