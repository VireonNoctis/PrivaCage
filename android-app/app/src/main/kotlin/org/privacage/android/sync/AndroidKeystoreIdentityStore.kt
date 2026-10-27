package org.privacage.android.sync

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import org.privacage.android.StrictJsonKeyScanner
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores identity material and relay bearer capabilities in app-private storage encrypted by
 * an AES-GCM key held by Android Keystore. The Rust identity bundle is itself passphrase-encrypted.
 */
internal class AndroidKeystoreIdentityStore(context: Context) {
    private val appContext = context.applicationContext
    private val recordFile = File(File(appContext.filesDir, DIRECTORY_NAME), FILE_NAME)

    @Throws(IOException::class)
    fun loadRecord(): JSONObject? {
        if (!recordFile.exists()) return null
        if (!recordFile.isFile || recordFile.length() !in 1..MAX_RECORD_FILE_BYTES.toLong()) {
            throw IOException("The protected sync record has an invalid size or type; it was not changed.")
        }
        val wrapperBytes = try {
            recordFile.readBytes()
        } catch (exception: Exception) {
            throw IOException("The protected sync record could not be read; it was not overwritten.", exception)
        }
        val wrapper = try {
            val wrapperText = decodeUtf8Strict(wrapperBytes, "Protected sync envelope")
            StrictJsonKeyScanner.validate(wrapperText, "Protected sync envelope")
            JSONObject(wrapperText).also {
                requireExactKeys(it, setOf("version", "iv", "ciphertext"), "Protected sync envelope")
            }
        } catch (exception: Exception) {
            throw IOException("The protected sync record is damaged or ambiguous; it was not overwritten.", exception)
        } finally {
            wrapperBytes.fill(0)
        }
        if (wrapper.optInt("version", -1) != ENVELOPE_VERSION) {
            throw IOException("Unsupported protected sync envelope version; the file was preserved.")
        }
        val iv = try {
            Base64.decode(wrapper.getString("iv"), Base64.NO_WRAP)
        } catch (exception: Exception) {
            throw IOException("The protected sync record has an invalid IV; it was not overwritten.", exception)
        }
        val ciphertext = try {
            Base64.decode(wrapper.getString("ciphertext"), Base64.NO_WRAP)
        } catch (exception: Exception) {
            throw IOException("The protected sync record has invalid ciphertext; it was not overwritten.", exception)
        }
        if (iv.size != GCM_IV_BYTES || ciphertext.size < GCM_TAG_BYTES) {
            throw IOException("The protected sync record has an invalid cryptographic envelope; it was not overwritten.")
        }

        val key = loadExistingKey()
        val cleartext = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.updateAAD(AAD)
            cipher.doFinal(ciphertext)
        } catch (exception: GeneralSecurityException) {
            throw IOException(
                "Android Keystore could not authenticate this sync record. The stored file was preserved.",
                exception
            )
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }

        return try {
            val cleartextJson = decodeUtf8Strict(cleartext, "Decrypted sync record")
            StrictJsonKeyScanner.validate(cleartextJson, "Decrypted sync record")
            JSONObject(cleartextJson).also {
                if (it.optInt("record_version", -1) != RECORD_VERSION) {
                    throw IOException("Unsupported protected sync record version; the file was preserved.")
                }
            }
        } catch (exception: IOException) {
            throw exception
        } catch (exception: Exception) {
            throw IOException("The decrypted sync record is invalid; the file was preserved.", exception)
        } finally {
            cleartext.fill(0)
        }
    }

    @Throws(IOException::class)
    fun saveRecord(record: JSONObject, replaceMissingKeystoreKey: Boolean = false) {
        val cleartext = record.toString().toByteArray(StandardCharsets.UTF_8)
        if (cleartext.size > MAX_RECORD_PLAINTEXT_BYTES) {
            cleartext.fill(0)
            throw IOException("Protected sync settings exceed the supported size.")
        }
        val cipherText: ByteArray
        val iv: ByteArray
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(replaceMissingKeystoreKey))
            cipher.updateAAD(AAD)
            cipherText = cipher.doFinal(cleartext)
            iv = cipher.iv
        } catch (exception: GeneralSecurityException) {
            cleartext.fill(0)
            throw IOException("Android Keystore could not encrypt the sync record.", exception)
        } finally {
            cleartext.fill(0)
        }

        val wrapper = JSONObject()
            .put("version", ENVELOPE_VERSION)
            .put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
            .put("ciphertext", Base64.encodeToString(cipherText, Base64.NO_WRAP))
        iv.fill(0)
        cipherText.fill(0)

        val parent = recordFile.parentFile
            ?: throw IOException("Protected sync storage has no parent directory.")
        if (!parent.exists() && !parent.mkdirs()) {
            throw IOException("Could not create app-private sync storage.")
        }
        val temporary = File(parent, "$FILE_NAME.tmp")
        val wrappedBytes = wrapper.toString().toByteArray(StandardCharsets.UTF_8)
        try {
            FileOutputStream(temporary).use { output ->
                output.write(wrappedBytes)
                output.fd.sync()
            }
            try {
                Files.move(
                    temporary.toPath(),
                    recordFile.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE
                )
            } catch (exception: Exception) {
                throw IOException("Could not atomically update the protected sync record.", exception)
            }
        } finally {
            wrappedBytes.fill(0)
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun decodeUtf8Strict(bytes: ByteArray, label: String): String = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            .decode(java.nio.ByteBuffer.wrap(bytes))
            .toString()
    } catch (exception: Exception) {
        throw IOException("$label is not valid UTF-8.", exception)
    }

    private fun requireExactKeys(value: JSONObject, expected: Set<String>, label: String) {
        val actual = mutableSetOf<String>()
        val iterator = value.keys()
        while (iterator.hasNext()) actual += iterator.next()
        if (actual != expected) throw IOException("$label has unsupported or missing fields.")
    }

    private fun loadExistingKey(): SecretKey {
        val existing = androidKeyStore().getKey(KEY_ALIAS, null) as? SecretKey
        return existing ?: throw IOException(
            "The Android Keystore key for the saved sync record is missing. " +
                "The encrypted file was preserved; import your recovery bundle rather than overwriting it."
        )
    }

    private fun getOrCreateKey(allowMissingKeyReplacement: Boolean): SecretKey {
        val keyStore = androidKeyStore()
        val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        if (recordFile.exists() && !allowMissingKeyReplacement) return loadExistingKey()

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun androidKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    companion object {
        private const val DIRECTORY_NAME = "privacage-sync"
        private const val FILE_NAME = "identity-record-v1.enc"
        private const val KEY_ALIAS = "org.privacage.android.sync.identity.v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val RECORD_VERSION = 1
        private const val ENVELOPE_VERSION = 1
        private const val GCM_TAG_BITS = 128
        private const val GCM_IV_BYTES = 12
        private const val GCM_TAG_BYTES = 16
        private const val MAX_RECORD_PLAINTEXT_BYTES = 1_100_000
        private const val MAX_RECORD_FILE_BYTES = 1_500_000L
        private val AAD = "PrivaCage Android sync record v1".toByteArray(StandardCharsets.UTF_8)
    }
}
