package org.privacage.android

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-256-GCM envelope helpers kept independent of Android Keystore so JVM tests can exercise
 * authentication, tamper detection, and strict size/schema checks.
 */
internal object SensitivePreferenceEnvelope {
    private const val VERSION = 1
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private const val TAG_BYTES = TAG_BITS / 8

    fun encrypt(
        plaintext: String,
        key: SecretKey,
        aadLabel: String,
        maximumPlaintextBytes: Int
    ): String {
        validateLimits(aadLabel, maximumPlaintextBytes)
        val cleartext = plaintext.toByteArray(StandardCharsets.UTF_8)
        if (cleartext.isEmpty() || cleartext.size > maximumPlaintextBytes) {
            cleartext.fill(0)
            throw IOException("Encrypted local data is empty or exceeds its supported size.")
        }

        var iv = byteArrayOf()
        var ciphertext = byteArrayOf()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(aad(aadLabel))
            ciphertext = cipher.doFinal(cleartext)
            iv = cipher.iv
            if (iv.size != IV_BYTES || ciphertext.size < TAG_BYTES) {
                throw IOException("The cryptographic provider returned an invalid local-data envelope.")
            }

            val envelope = JSONObject()
                .put("version", VERSION)
                .put("iv", Base64.getEncoder().encodeToString(iv))
                .put("ciphertext", Base64.getEncoder().encodeToString(ciphertext))
                .toString()
            if (envelope.toByteArray(StandardCharsets.UTF_8).size > maximumEnvelopeBytes(maximumPlaintextBytes)) {
                throw IOException("Encrypted local data exceeds its supported envelope size.")
            }
            return envelope
        } catch (exception: IOException) {
            throw exception
        } catch (exception: Exception) {
            throw IOException("Could not encrypt local data.", exception)
        } finally {
            cleartext.fill(0)
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    fun decrypt(
        envelopeText: String,
        key: SecretKey,
        aadLabel: String,
        maximumPlaintextBytes: Int
    ): String {
        validateLimits(aadLabel, maximumPlaintextBytes)
        val envelopeBytes = envelopeText.toByteArray(StandardCharsets.UTF_8)
        if (envelopeBytes.isEmpty() || envelopeBytes.size > maximumEnvelopeBytes(maximumPlaintextBytes)) {
            envelopeBytes.fill(0)
            throw IOException("Encrypted local data has an invalid envelope size; stored data was preserved.")
        }

        val envelope = try {
            StrictJsonKeyScanner.validate(envelopeText, "Encrypted local preference envelope")
            JSONObject(envelopeText)
        } catch (exception: Exception) {
            throw IOException("Encrypted local preference envelope is malformed or ambiguous; stored data was preserved.", exception)
        } finally {
            envelopeBytes.fill(0)
        }

        if (envelope.keys().asSequence().toSet() != setOf("version", "iv", "ciphertext") ||
            envelope.opt("version") !is Int || envelope.optInt("version") != VERSION
        ) {
            throw IOException("Encrypted local preference envelope has unsupported fields or version; stored data was preserved.")
        }

        var iv = byteArrayOf()
        var ciphertext = byteArrayOf()
        var cleartext = byteArrayOf()
        try {
            iv = try {
                Base64.getDecoder().decode(envelope.getString("iv"))
            } catch (exception: Exception) {
                throw IOException("Encrypted local preference envelope has an invalid IV; stored data was preserved.", exception)
            }
            ciphertext = try {
                Base64.getDecoder().decode(envelope.getString("ciphertext"))
            } catch (exception: Exception) {
                throw IOException("Encrypted local preference envelope has invalid ciphertext; stored data was preserved.", exception)
            }
            if (iv.size != IV_BYTES || ciphertext.size !in TAG_BYTES..(maximumPlaintextBytes + TAG_BYTES)) {
                throw IOException("Encrypted local preference envelope has invalid cryptographic lengths; stored data was preserved.")
            }

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(aad(aadLabel))
            cleartext = cipher.doFinal(ciphertext)
            if (cleartext.isEmpty() || cleartext.size > maximumPlaintextBytes) {
                throw IOException("Decrypted local data exceeds its supported size; stored data was preserved.")
            }
            return try {
                StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(cleartext))
                    .toString()
            } catch (exception: Exception) {
                throw IOException("Decrypted local data is not valid UTF-8; stored data was preserved.", exception)
            }
        } catch (exception: IOException) {
            throw exception
        } catch (exception: GeneralSecurityException) {
            throw IOException("Android Keystore could not authenticate local data; stored ciphertext was preserved.", exception)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
            cleartext.fill(0)
        }
    }

    private fun aad(label: String): ByteArray =
        ("org.privacage.android private preference v1|" + label)
            .toByteArray(StandardCharsets.UTF_8)

    private fun validateLimits(label: String, maximum: Int) {
        require(label.matches(Regex("^[a-z0-9][a-z0-9._-]{0,63}$"))) {
            "Local encryption label is invalid."
        }
        require(maximum in 1..(8 * 1024 * 1024)) {
            "Local encryption size limit is outside the supported range."
        }
    }

    private fun maximumEnvelopeBytes(maximumPlaintextBytes: Int): Int =
        Math.addExact(Math.multiplyExact(maximumPlaintextBytes, 2), 4096)
}

/**
 * Encrypts selected app-private preferences with independently named Android Keystore keys.
 * Legacy plaintext keys are removed only in the same synchronous commit that stores a validated
 * encrypted replacement. Existing ciphertext is never replaced if its key or authentication fails.
 */
internal object AndroidSensitivePreferenceVault {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    @Synchronized
    @Throws(IOException::class)
    fun read(
        context: Context,
        preferencesName: String,
        encryptedKey: String,
        keyAlias: String,
        aadLabel: String,
        defaultValue: String?,
        maximumPlaintextBytes: Int,
        legacyKeys: Set<String> = emptySet(),
        legacyValue: (() -> String?)? = null,
        validateValue: (String) -> Unit
    ): String? {
        val preferences = context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE)
        if (preferences.contains(encryptedKey)) {
            val envelope = readString(preferences, encryptedKey)
                ?: throw IOException("The encrypted local preference is missing its value; stored data was preserved.")
            val cleartext = SensitivePreferenceEnvelope.decrypt(
                envelope,
                loadExistingKey(keyAlias),
                aadLabel,
                maximumPlaintextBytes
            )
            try {
                validateValue(cleartext)
            } catch (exception: Exception) {
                throw IOException("Decrypted local preference failed validation; stored data was preserved.", exception)
            }
            return cleartext
        }

        if (legacyKeys.none(preferences::contains)) return defaultValue

        val legacy = try {
            legacyValue?.invoke()
        } catch (exception: Exception) {
            throw IOException("Legacy local preference could not be read; plaintext data was preserved.", exception)
        } ?: throw IOException("Legacy local preference is missing or has an unexpected stored type; data was preserved.")

        val bytes = legacy.toByteArray(StandardCharsets.UTF_8)
        try {
            if (bytes.isEmpty() || bytes.size > maximumPlaintextBytes) {
                throw IOException("Legacy local preference exceeds its supported size; plaintext data was preserved.")
            }
        } finally {
            bytes.fill(0)
        }
        try {
            validateValue(legacy)
        } catch (exception: Exception) {
            throw IOException("Legacy local preference failed validation; plaintext data was preserved.", exception)
        }

        val envelope = SensitivePreferenceEnvelope.encrypt(
            legacy,
            getOrCreateKey(keyAlias),
            aadLabel,
            maximumPlaintextBytes
        )
        val editor = preferences.edit().putString(encryptedKey, envelope)
        legacyKeys.forEach { editor.remove(it) }
        if (!editor.commit()) {
            throw IOException("Could not confirm encrypted preference migration; legacy data was not intentionally cleared.")
        }
        return legacy
    }

    @Synchronized
    @Throws(IOException::class)
    fun write(
        context: Context,
        preferencesName: String,
        encryptedKey: String,
        keyAlias: String,
        aadLabel: String,
        plaintext: String,
        maximumPlaintextBytes: Int,
        legacyKeys: Set<String> = emptySet(),
        validateValue: (String) -> Unit
    ) {
        try {
            validateValue(plaintext)
        } catch (exception: Exception) {
            throw IOException("Local preference was not saved because validation failed.", exception)
        }
        val preferences = context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE)
        val key = if (preferences.contains(encryptedKey)) {
            loadExistingKey(keyAlias)
        } else {
            getOrCreateKey(keyAlias)
        }
        val envelope = SensitivePreferenceEnvelope.encrypt(
            plaintext,
            key,
            aadLabel,
            maximumPlaintextBytes
        )
        val editor = preferences.edit().putString(encryptedKey, envelope)
        legacyKeys.forEach { editor.remove(it) }
        if (!editor.commit()) {
            throw IOException("Android did not confirm the encrypted local preference write.")
        }
    }

    @Synchronized
    fun clear(
        context: Context,
        preferencesName: String,
        encryptedKey: String,
        legacyKeys: Set<String> = emptySet()
    ): Boolean {
        val editor = context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE)
            .edit()
            .remove(encryptedKey)
        legacyKeys.forEach { editor.remove(it) }
        return editor.commit()
    }

    private fun readString(preferences: SharedPreferences, key: String): String? = try {
        preferences.getString(key, null)
    } catch (exception: ClassCastException) {
        throw IOException("Encrypted local preference has an unexpected stored type; data was preserved.", exception)
    }

    private fun loadExistingKey(alias: String): SecretKey {
        validateAlias(alias)
        val key = androidKeyStore().getKey(alias, null) as? SecretKey
        return key ?: throw IOException(
            "The Android Keystore key for existing encrypted data is missing. Stored ciphertext was preserved; no replacement key was created."
        )
    }

    private fun getOrCreateKey(alias: String): SecretKey {
        validateAlias(alias)
        val store = androidKeyStore()
        val existing = store.getKey(alias, null) as? SecretKey
        if (existing != null) return existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun androidKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun validateAlias(alias: String) {
        require(alias.matches(Regex("^[A-Za-z0-9._-]{1,120}$"))) {
            "Android Keystore alias is invalid."
        }
    }
}
