package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Test

class CertificateFingerprintTest {
    @Test
    fun sha256UsesLowercaseHexAndKnownDigest() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            CertificateFingerprint.sha256("abc".toByteArray(Charsets.US_ASCII))
        )
    }

    @Test
    fun emptyInputHasStableSha256() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            CertificateFingerprint.sha256(byteArrayOf())
        )
    }
}
