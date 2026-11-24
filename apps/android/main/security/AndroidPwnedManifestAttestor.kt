package org.privacage.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec

/**
 * Creates a dedicated local P-256 signing key only after the user requests an export.
 * If an existing alias is present but unusable, export fails instead of replacing it.
 * If the alias is absent, the explicit export action creates a new key; compare its fingerprint out of band.
 */
internal object AndroidPwnedManifestAttestor {
    private const val KEY_ALIAS = "org.privacage.pwned.manifest.attestation.p256.v1"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    @Throws(IOException::class)
    fun sign(manifestSha256: String): SignedPwnedManifestAttestation {
        val keyPair = loadOrCreateKeyPair()
        return PwnedPasswordManifestAttestation.sign(
            manifestSha256 = manifestSha256,
            privateKey = keyPair.private,
            publicKey = keyPair.public
        )
    }

    @Throws(IOException::class)
    private fun loadOrCreateKeyPair(): KeyPair {
        try {
            var keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                generator.initialize(
                    KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setUserAuthenticationRequired(false)
                        .build()
                )
                generator.generateKeyPair()
                keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            }

            val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
                ?: throw IOException("The local attestation key exists but its private-key handle is unavailable; it was not replaced.")
            val publicKey = keyStore.getCertificate(KEY_ALIAS)?.publicKey
                ?: throw IOException("The local attestation key has no public-key certificate; it was not replaced.")
            return KeyPair(publicKey, privateKey)
        } catch (exception: IOException) {
            throw exception
        } catch (exception: GeneralSecurityException) {
            throw IOException("Android Keystore could not create or access the local manifest-attestation key.", exception)
        } catch (exception: RuntimeException) {
            throw IOException("Android Keystore could not create or access the local manifest-attestation key.", exception)
        }
    }
}
