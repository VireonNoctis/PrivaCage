package org.privacage.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Versioned, portable encrypted container for small PrivaCage profile exports.
 *
 * Format v1: 8-byte magic, 16-byte salt, 12-byte nonce, then AES-GCM ciphertext plus a 16-byte tag.
 * The complete 36-byte header is authenticated as AES-GCM associated data.
 */
object EncryptedBackupEnvelope {
    const val MIN_PASSPHRASE_LENGTH = 12
    const val MAX_PLAINTEXT_BYTES = 1_048_576
    const val MAX_ENVELOPE_BYTES = MAX_PLAINTEXT_BYTES + 52

    private const val MAGIC_SIZE = 8
    private const val SALT_SIZE = 16
    private const val NONCE_SIZE = 12
    private const val KEY_SIZE = 32
    private const val TAG_SIZE_BYTES = 16
    private const val TAG_SIZE_BITS = TAG_SIZE_BYTES * 8
    private const val HEADER_SIZE = MAGIC_SIZE + SALT_SIZE + NONCE_SIZE
    private const val ARGON_MEMORY_KIB = 19_456
    private const val ARGON_ITERATIONS = 2
    private const val ARGON_PARALLELISM = 1
    private const val MAX_PASSPHRASE_CHARACTERS = 1_024
    private const val MAX_PASSPHRASE_BYTES = 4_096

    private val magic = byteArrayOf(
        0x50.toByte(), 0x43.toByte(), 0x41.toByte(), 0x47.toByte(),
        0x45.toByte(), 0x30.toByte(), 0x31.toByte(), 0x00
    )
    private val secureRandom = SecureRandom()

    @Throws(GeneralSecurityException::class)
    fun encrypt(plaintext: ByteArray, passphrase: CharArray): ByteArray {
        require(plaintext.size <= MAX_PLAINTEXT_BYTES) {
            "Profile data exceeds the maximum supported size"
        }
        val passwordBytes = encodePassphrase(passphrase)
        val salt = ByteArray(SALT_SIZE)
        val nonce = ByteArray(NONCE_SIZE)
        secureRandom.nextBytes(salt)
        secureRandom.nextBytes(nonce)
        val header = ByteArray(HEADER_SIZE)
        magic.copyInto(header, 0)
        salt.copyInto(header, MAGIC_SIZE)
        nonce.copyInto(header, MAGIC_SIZE + SALT_SIZE)

        try {
            val key = deriveKey(passwordBytes, salt)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE_BITS, nonce))
                cipher.updateAAD(header)
                val encryptedPayload = cipher.doFinal(plaintext)
                try {
                    val output = ByteArray(header.size + encryptedPayload.size)
                    header.copyInto(output)
                    encryptedPayload.copyInto(output, header.size)
                    return output
                } finally {
                    encryptedPayload.fill(0)
                }
            } finally {
                key.fill(0)
            }
        } finally {
            passwordBytes.fill(0)
            salt.fill(0)
            nonce.fill(0)
            header.fill(0)
        }
    }

    @Throws(GeneralSecurityException::class)
    fun decrypt(envelope: ByteArray, passphrase: CharArray): ByteArray {
        require(envelope.size in (HEADER_SIZE + TAG_SIZE_BYTES)..MAX_ENVELOPE_BYTES) {
            "Encrypted backup length is invalid"
        }
        for (index in magic.indices) {
            require(envelope[index] == magic[index]) { "Unsupported encrypted backup format" }
        }

        val passwordBytes = encodePassphrase(passphrase)
        val header = envelope.copyOfRange(0, HEADER_SIZE)
        val salt = envelope.copyOfRange(MAGIC_SIZE, MAGIC_SIZE + SALT_SIZE)
        val nonce = envelope.copyOfRange(MAGIC_SIZE + SALT_SIZE, HEADER_SIZE)
        try {
            val key = deriveKey(passwordBytes, salt)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE_BITS, nonce))
                cipher.updateAAD(header)
                return cipher.doFinal(envelope, HEADER_SIZE, envelope.size - HEADER_SIZE)
            } finally {
                key.fill(0)
            }
        } finally {
            passwordBytes.fill(0)
            header.fill(0)
            salt.fill(0)
            nonce.fill(0)
        }
    }

    private fun encodePassphrase(passphrase: CharArray): ByteArray {
        require(passphrase.size in MIN_PASSPHRASE_LENGTH..MAX_PASSPHRASE_CHARACTERS) {
            "Passphrase must contain at least $MIN_PASSPHRASE_LENGTH characters"
        }
        var encoded: ByteBuffer? = null
        try {
            val encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            encoded = encoder.encode(CharBuffer.wrap(passphrase))
            val bytes = ByteArray(encoded.remaining())
            encoded.get(bytes)
            if (bytes.size !in MIN_PASSPHRASE_LENGTH..MAX_PASSPHRASE_BYTES) {
                bytes.fill(0)
                throw IllegalArgumentException("Passphrase UTF-8 length is outside supported limits")
            }
            return bytes
        } catch (exception: CharacterCodingException) {
            throw IllegalArgumentException("Passphrase contains invalid Unicode", exception)
        } finally {
            encoded?.let { buffer ->
                if (buffer.hasArray()) buffer.array().fill(0)
            }
        }
    }

    private fun deriveKey(passwordBytes: ByteArray, salt: ByteArray): ByteArray {
        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(ARGON_MEMORY_KIB)
            .withIterations(ARGON_ITERATIONS)
            .withParallelism(ARGON_PARALLELISM)
            .withSalt(salt)
        val parameters = builder.build()
        val generator = Argon2BytesGenerator()
        val key = ByteArray(KEY_SIZE)
        try {
            generator.init(parameters)
            generator.generateBytes(passwordBytes, key)
            return key
        } catch (exception: Exception) {
            key.fill(0)
            throw exception
        } finally {
            // Bouncy Castle 1.86 resets and clears its internal Argon2 block pool during generation.
            parameters.clear()
            builder.clear()
        }
    }
}
