package org.privacage.android

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.Base64
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class LocalDnsHistoryCipherTest {
    @Test
    fun encryptedEnvelopeRoundTripsWithoutExposingTheHostname() {
        val hostname = "private-domain.example"
        val serialized = """[{"timestamp":"2026-10-26T10:00:00Z","domain":"private-domain.example","action":"FORWARDED","socket_owner":"Unknown"}]"""
        val secret = key()
        val envelope = LocalDnsHistoryCipher.encrypt(serialized, secret)

        assertFalse(envelope.contains(hostname))
        assertEquals(serialized, LocalDnsHistoryCipher.decrypt(envelope, secret))
    }

    @Test
    fun wrongKeyCannotAuthenticateTheEnvelope() {
        val envelope = LocalDnsHistoryCipher.encrypt("""[{"domain":"private-domain.example"}]""", key())

        assertIOException("authenticate") {
            LocalDnsHistoryCipher.decrypt(envelope, key())
        }
    }

    @Test
    fun tamperedCiphertextIsRejected() {
        val secret = key()
        val envelope = JSONObject(LocalDnsHistoryCipher.encrypt("""[{"domain":"example.org"}]""", secret))
        val ciphertext = Base64.getDecoder().decode(envelope.getString("ciphertext"))
        ciphertext[0] = (ciphertext[0].toInt() xor 1).toByte()
        envelope.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext))

        assertIOException("authenticate") {
            LocalDnsHistoryCipher.decrypt(envelope.toString(), secret)
        }
    }

    @Test
    fun duplicateEnvelopeFieldsAreRejectedBeforeJsonParsing() {
        val secret = key()
        val valid = JSONObject(LocalDnsHistoryCipher.encrypt("[]", secret))
        val iv = valid.getString("iv")
        val ciphertext = valid.getString("ciphertext")
        val duplicate = """{"version":1,"version":1,"iv":"${iv}","ciphertext":"${ciphertext}"}"""
        assertIOException("ambiguous") {
            LocalDnsHistoryCipher.decrypt(duplicate, secret)
        }
    }

    @Test
    fun unsupportedVersionIsRejected() {
        val secret = key()
        val envelope = JSONObject(LocalDnsHistoryCipher.encrypt("[]", secret)).put("version", 2)

        assertIOException("version") {
            LocalDnsHistoryCipher.decrypt(envelope.toString(), secret)
        }
    }

    @Test
    fun additionalEnvelopeFieldsAreRejected() {
        val secret = key()
        val envelope = JSONObject(LocalDnsHistoryCipher.encrypt("[]", secret)).put("fallback_plaintext", "private")

        assertIOException("fields") {
            LocalDnsHistoryCipher.decrypt(envelope.toString(), secret)
        }
    }

    @Test
    fun malformedIvIsRejected() {
        val secret = key()
        val envelope = JSONObject(LocalDnsHistoryCipher.encrypt("[]", secret))
            .put("iv", Base64.getEncoder().encodeToString(byteArrayOf(1, 2)))

        assertIOException("lengths") {
            LocalDnsHistoryCipher.decrypt(envelope.toString(), secret)
        }
    }

    @Test
    fun oversizedPlaintextIsRejectedBeforeEncryption() {
        assertIOException("limit") {
            LocalDnsHistoryCipher.encrypt("x".repeat(LocalDnsHistoryCipher.MAX_PLAINTEXT_BYTES + 1), key())
        }
    }

    private fun key(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    private fun assertIOException(messagePart: String? = null, action: () -> Unit) {
        try {
            action()
            throw AssertionError("Expected encrypted history operation to fail")
        } catch (exception: IOException) {
            if (messagePart != null) {
                assertTrue(
                    "Unexpected error: " + exception.message,
                    exception.message?.contains(messagePart, ignoreCase = true) == true
                )
            }
        }
    }
}
