package org.privacage.security

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PwnedPasswordManifestAttestationTest {
    private val repositoryRoot: Path
        get() = Path.of(
            System.getProperty("privacage.repo-root")
                ?: error("Missing privacage.repo-root test property")
        )

    private val attestationFixtureRoot: Path
        get() = repositoryRoot.resolve("shared/crypto/test-vectors/pwned-password-attestation/v1")

    private fun fixtureJson(): String =
        String(
            Files.readAllBytes(attestationFixtureRoot.resolve("attestation.json")),
            StandardCharsets.UTF_8
        )

    private fun trustedFingerprint(): String =
        String(
            Files.readAllBytes(attestationFixtureRoot.resolve("trusted-public-key-sha256.txt")),
            StandardCharsets.US_ASCII
        ).trim()

    @Test
    fun verifiesSharedGoAttestationVectorAndExactManifestDigest() {
        val verified = PwnedPasswordManifestAttestation.verify(fixtureJson(), trustedFingerprint())
        val expectedManifestDigest = String(
            Files.readAllBytes(
                repositoryRoot.resolve("shared/crypto/test-vectors/pwned-password-manifest/v1/manifest.sha256")
            ),
            StandardCharsets.US_ASCII
        ).trim()
        assertEquals(expectedManifestDigest, verified.manifestSha256)
        assertEquals(trustedFingerprint(), verified.signerPublicKeySha256)
    }

    @Test
    fun signsAndVerifiesWithAGeneratedP256KeyPair() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = generator.generateKeyPair()
        val digest = "BB5A8AA3754FD3A62A59C679441858269D2534D94129826F78FA26FFC6FACD91"
        val signed = PwnedPasswordManifestAttestation.sign(digest, keyPair.private, keyPair.public)
        val verified = PwnedPasswordManifestAttestation.verify(signed.json, signed.signerPublicKeySha256)
        assertEquals(digest, signed.manifestSha256)
        assertEquals(digest, verified.manifestSha256)
        assertEquals(signed.signerPublicKeySha256, verified.signerPublicKeySha256)
    }

    @Test
    fun rejectsWrongTrustAnchorAndTamperedManifestDigest() {
        val original = fixtureJson()
        assertFailsWith<IOException> {
            PwnedPasswordManifestAttestation.verify(original, "0".repeat(64))
        }
        val tampered = original.replaceFirst(
            "BB5A8AA3754FD3A62A59C679441858269D2534D94129826F78FA26FFC6FACD91",
            "A".repeat(64)
        )
        assertTrue(tampered != original)
        assertFailsWith<IOException> {
            PwnedPasswordManifestAttestation.verify(tampered, trustedFingerprint())
        }
    }

    @Test
    fun rejectsDuplicateUnknownAndNonCanonicalFields() {
        val original = fixtureJson()
        val duplicate = original.replaceFirst("\"version\": 1", "\"version\": 1,\"version\": 1")
        assertFailsWith<IOException> {
            PwnedPasswordManifestAttestation.verify(duplicate, trustedFingerprint())
        }
        val unknown = original.replaceFirst("{", "{\"unexpected\":true,")
        assertFailsWith<IOException> {
            PwnedPasswordManifestAttestation.verify(unknown, trustedFingerprint())
        }
        val nonCanonical = original.replaceFirst("\"version\": 1", "\"version\": 1.0")
        assertFailsWith<IOException> {
            PwnedPasswordManifestAttestation.verify(nonCanonical, trustedFingerprint())
        }
    }

    @Test
    fun rejectsNonP256SigningKeys() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp384r1"))
        val keyPair = generator.generateKeyPair()
        assertFailsWith<IOException> {
            PwnedPasswordManifestAttestation.sign(
                "BB5A8AA3754FD3A62A59C679441858269D2534D94129826F78FA26FFC6FACD91",
                keyPair.private,
                keyPair.public
            )
        }
    }
}
