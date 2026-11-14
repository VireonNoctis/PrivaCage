package org.privacage.crypto

import java.security.GeneralSecurityException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class EncryptedBackupEnvelopeTest {
    private val passphrase = "correct horse battery staple".toCharArray()

    @Test
    fun decryptsSharedRustInteroperabilityVector() {
        val envelopeHex = requireNotNull(javaClass.getResourceAsStream("/pcage-v1-envelope.hex"))
            .bufferedReader(Charsets.US_ASCII).use { it.readText() }
            .filterNot(Char::isWhitespace)
        val envelope = envelopeHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val expectedPlaintext = requireNotNull(javaClass.getResourceAsStream("/pcage-v1-plaintext.json"))
            .use { it.readBytes() }
        val passphrase = "correct horse battery staple".toCharArray()
        try {
            val plaintext = EncryptedBackupEnvelope.decrypt(envelope, passphrase)
            assertContentEquals(expectedPlaintext, plaintext)
            plaintext.fill(0)
        } finally {
            passphrase.fill(0.toChar())
            envelope.fill(0)
        }
    }

    @Test
    fun roundTripsBinaryPayload() {
        val plaintext = byteArrayOf(0, 1, 2, 3, 0, -1, 42)
        val encrypted = EncryptedBackupEnvelope.encrypt(plaintext, passphrase)
        val decrypted = EncryptedBackupEnvelope.decrypt(encrypted, passphrase)
        assertContentEquals(plaintext, decrypted)
        assertTrue(!encrypted.toString(Charsets.ISO_8859_1).contains("correct horse battery staple"))
        decrypted.fill(0)
        encrypted.fill(0)
    }

    @Test
    fun differentExportsUseDifferentRandomSaltsAndNonces() {
        val first = EncryptedBackupEnvelope.encrypt(byteArrayOf(1, 2, 3), passphrase)
        val second = EncryptedBackupEnvelope.encrypt(byteArrayOf(1, 2, 3), passphrase)
        assertNotEquals(first.take(36), second.take(36))
        first.fill(0)
        second.fill(0)
    }

    @Test
    fun rejectsWrongPassphrase() {
        val encrypted = EncryptedBackupEnvelope.encrypt("secret".toByteArray(), passphrase)
        val wrong = "a different strong passphrase".toCharArray()
        try {
            assertFailsWith<GeneralSecurityException> {
                EncryptedBackupEnvelope.decrypt(encrypted, wrong)
            }
        } finally {
            wrong.fill('\u0000')
            encrypted.fill(0)
        }
    }

    @Test
    fun rejectsCiphertextTampering() {
        val encrypted = EncryptedBackupEnvelope.encrypt("secret".toByteArray(), passphrase)
        encrypted[encrypted.size - 17] = (encrypted[encrypted.size - 17].toInt() xor 0x40).toByte()
        assertFailsWith<GeneralSecurityException> {
            EncryptedBackupEnvelope.decrypt(encrypted, passphrase)
        }
        encrypted.fill(0)
    }

    @Test
    fun rejectsAuthenticatedHeaderTampering() {
        val encrypted = EncryptedBackupEnvelope.encrypt("secret".toByteArray(), passphrase)
        encrypted[8] = (encrypted[8].toInt() xor 1).toByte()
        assertFailsWith<GeneralSecurityException> {
            EncryptedBackupEnvelope.decrypt(encrypted, passphrase)
        }
        encrypted.fill(0)
    }

    @Test
    fun rejectsUnknownVersionAndTruncatedFiles() {
        val encrypted = EncryptedBackupEnvelope.encrypt("secret".toByteArray(), passphrase)
        val unknownVersion = encrypted.copyOf().apply { this[6] = '2'.code.toByte() }
        assertFails { EncryptedBackupEnvelope.decrypt(unknownVersion, passphrase) }
        assertFails { EncryptedBackupEnvelope.decrypt(encrypted.copyOf(20), passphrase) }
        encrypted.fill(0)
        unknownVersion.fill(0)
    }

    @Test
    fun rejectsPassphrasesThatAreTooShort() {
        assertFails {
            EncryptedBackupEnvelope.encrypt(byteArrayOf(1), "short".toCharArray())
        }
    }

    @Test
    fun rejectsOversizedPlaintext() {
        assertFails {
            EncryptedBackupEnvelope.encrypt(
                ByteArray(EncryptedBackupEnvelope.MAX_PLAINTEXT_BYTES + 1),
                passphrase
            )
        }
    }

    @Test
    fun rejectsMalformedUtf16Passphrase() {
        assertFails {
            EncryptedBackupEnvelope.encrypt(byteArrayOf(1), CharArray(12) { '\uD800' })
        }
    }
}
