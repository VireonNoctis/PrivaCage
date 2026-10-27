package org.privacage.android

import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Versioned AES-GCM wrapper for optional local DNS history.
 *
 * Production storage supplies a key held by Android Keystore. The key is injected here so tests
 * can verify the envelope and authentication behavior without an Android Keystore provider.
 */
internal object LocalDnsHistoryCipher {
    const val MAX_PLAINTEXT_BYTES = 256 * 1024
    private const val MAX_ENVELOPE_BYTES = 400 * 1024
    private const val ENVELOPE_VERSION = 1
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val GCM_TAG_BYTES = GCM_TAG_BITS / 8
    private val AAD = "PrivaCage local DNS history envelope v1".toByteArray(StandardCharsets.UTF_8)

    @Throws(IOException::class)
    fun encrypt(serialized: String, key: SecretKey): String {
        val cleartext = serialized.toByteArray(StandardCharsets.UTF_8)
        if (cleartext.size > MAX_PLAINTEXT_BYTES) {
            cleartext.fill(0)
            throw IOException("Local DNS history exceeds the 256 KiB plaintext limit.")
        }

        var iv = byteArrayOf()
        var ciphertext = byteArrayOf()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(AAD)
            ciphertext = cipher.doFinal(cleartext)
            iv = cipher.iv
            if (iv.size != GCM_IV_BYTES || ciphertext.size < GCM_TAG_BYTES) {
                throw IOException("The cryptographic provider returned an invalid DNS history envelope.")
            }

            val envelope = JSONObject()
                .put("version", ENVELOPE_VERSION)
                .put("iv", Base64.getEncoder().encodeToString(iv))
                .put("ciphertext", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            if (envelope.toByteArray(StandardCharsets.UTF_8).size > MAX_ENVELOPE_BYTES) {
                throw IOException("Encrypted DNS history exceeds the supported envelope size.")
            }
            return envelope
        } catch (exception: IOException) {
            throw exception
        } catch (exception: GeneralSecurityException) {
            throw IOException("Could not encrypt local DNS history.", exception)
        } catch (exception: JSONException) {
            throw IOException("Could not serialize encrypted DNS history.", exception)
        } finally {
            cleartext.fill(0)
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    @Throws(IOException::class)
    fun decrypt(envelopeText: String, key: SecretKey): String {
        val envelopeBytes = envelopeText.toByteArray(StandardCharsets.UTF_8)
        if (envelopeBytes.size > MAX_ENVELOPE_BYTES) {
            envelopeBytes.fill(0)
            throw IOException("Encrypted DNS history exceeds the supported envelope size; stored data was preserved.")
        }

        val envelope = try {
            StrictJsonKeyScanner.validate(envelopeText, "Encrypted DNS history envelope")
            JSONObject(envelopeText)
        } catch (exception: IOException) {
            throw IOException("Encrypted DNS history envelope is malformed or ambiguous; stored data was preserved.", exception)
        } catch (exception: JSONException) {
            throw IOException("Encrypted DNS history envelope is malformed; stored data was preserved.", exception)
        } finally {
            envelopeBytes.fill(0)
        }

        val actualKeys = mutableSetOf<String>()
        val iterator = envelope.keys()
        while (iterator.hasNext()) actualKeys += iterator.next()
        if (actualKeys != setOf("version", "iv", "ciphertext")) {
            throw IOException("Encrypted DNS history envelope has unsupported fields; stored data was preserved.")
        }

        val version = envelope.opt("version")
        if (version !is Int || version != ENVELOPE_VERSION) {
            throw IOException("Unsupported encrypted DNS history version; stored data was preserved.")
        }

        var iv = byteArrayOf()
        var ciphertext = byteArrayOf()
        var cleartext = byteArrayOf()
        try {
            iv = try {
                Base64.getDecoder().decode(envelope.getString("iv"))
            } catch (exception: Exception) {
                throw IOException("Encrypted DNS history has an invalid IV; stored data was preserved.", exception)
            }
            ciphertext = try {
                Base64.getDecoder().decode(envelope.getString("ciphertext"))
            } catch (exception: Exception) {
                throw IOException("Encrypted DNS history has invalid ciphertext; stored data was preserved.", exception)
            }
            if (iv.size != GCM_IV_BYTES || ciphertext.size !in GCM_TAG_BYTES..(MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES)) {
                throw IOException("Encrypted DNS history has invalid cryptographic lengths; stored data was preserved.")
            }

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.updateAAD(AAD)
            cleartext = cipher.doFinal(ciphertext)
            if (cleartext.size > MAX_PLAINTEXT_BYTES) {
                throw IOException("Decrypted DNS history exceeds the plaintext limit; stored data was preserved.")
            }

            return try {
                StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(cleartext))
                    .toString()
            } catch (exception: Exception) {
                throw IOException("Decrypted DNS history is not valid UTF-8; stored data was preserved.", exception)
            }
        } catch (exception: IOException) {
            throw exception
        } catch (exception: GeneralSecurityException) {
            throw IOException(
                "Android Keystore could not authenticate local DNS history. Stored ciphertext was preserved.",
                exception
            )
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
            cleartext.fill(0)
        }
    }
}
