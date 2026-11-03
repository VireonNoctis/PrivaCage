package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import javax.crypto.spec.SecretKeySpec

class AppPolicyReviewEnvelopeTest {
    private val key = SecretKeySpec(ByteArray(32) { (it + 11).toByte() }, "AES")
    private val otherKey = SecretKeySpec(ByteArray(32) { (it + 12).toByte() }, "AES")

    @Test
    fun authenticatesTheEncryptedReviewQueue() {
        val plaintext = """{"schema_version":1,"pending":[]}"""
        val encrypted = AppPolicyReviewEnvelope.encrypt(plaintext, key)

        assertEquals(plaintext, AppPolicyReviewEnvelope.decrypt(encrypted, key))
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewEnvelope.decrypt(encrypted, otherKey)
        }
    }

    @Test
    fun rejectsTamperingAndUnsupportedEnvelopeFields() {
        val encrypted = AppPolicyReviewEnvelope.encrypt("{}", key)
        val parsed = org.json.JSONObject(encrypted)
        val changed = parsed.getString("ciphertext").dropLast(2) + "AA"
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewEnvelope.decrypt(parsed.put("ciphertext", changed).toString(), key)
        }
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewEnvelope.decrypt(
                org.json.JSONObject(encrypted).put("extra", true).toString(),
                key
            )
        }
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewEnvelope.decrypt(
                encrypted.replace("\"version\":1", "\"version\":1,\"version\":1"),
                key
            )
        }
    }
}

class AppPolicyReviewStateTest {
    private val pending = PendingAppPolicyReview(
        packageName = "org.example.reader",
        trigger = "installed",
        firstSeenAt = 1_790_000_000_000L,
        lastSeenAt = 1_790_000_000_000L,
        termsUrl = "https://example.org/terms",
        privacyUrl = "https://example.org/privacy"
    )

    @Test
    fun stateRoundTripsWithAppInventoryAndPolicyLinks() {
        val state = AppPolicyReviewState(
            inventoryInitialized = true,
            knownPackages = setOf("org.example.reader", "org.example.notes"),
            reviewedPackages = setOf("org.example.notes"),
            lastUsageScanAt = 1_790_000_000_000L,
            pending = mapOf(pending.packageName to pending)
        )

        val decoded = AppPolicyReviewStore.decodeState(AppPolicyReviewStore.encodeState(state))
        assertEquals(state, decoded)
    }

    @Test
    fun rejectsNonHttpsAndCredentialBearingPolicyLinks() {
        assertThrows(IllegalArgumentException::class.java) {
            AppPolicyReviewStore.validatePolicyUrl("http://example.org/privacy")
        }
        assertThrows(IllegalArgumentException::class.java) {
            AppPolicyReviewStore.validatePolicyUrl("https://user:password@example.org/privacy")
        }
    }

    @Test
    fun rejectsDuplicateOrInvalidPackagesAndUnknownFields() {
        val state = AppPolicyReviewState(true, setOf("org.example.reader"), emptySet(), 0L, emptyMap())
        val encoded = AppPolicyReviewStore.encodeState(state)
            .replace("org.example.reader", "not-a-package")
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewStore.decodeState(encoded)
        }
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewStore.decodeState(
                org.json.JSONObject(AppPolicyReviewStore.encodeState(state))
                    .put("unexpected", true)
                    .toString()
            )
        }
    }

    @Test
    fun rejectsDuplicateKeysCoercedTimestampsAndInconsistentInventory() {
        val state = AppPolicyReviewState(true, setOf("org.example.reader"), emptySet(), 0L, emptyMap())
        val encoded = AppPolicyReviewStore.encodeState(state)
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewStore.decodeState(
                encoded.replace("\"inventory_initialized\":true", "\"inventory_initialized\":true,\"inventory_initialized\":false")
            )
        }
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewStore.decodeState(
                encoded.replace("\"last_usage_scan_at\":0", "\"last_usage_scan_at\":\"0\"")
            )
        }
        val inconsistent = state.copy(reviewedPackages = setOf("org.example.other"))
        assertThrows(IllegalArgumentException::class.java) {
            AppPolicyReviewStore.encodeState(inconsistent)
        }
    }
}

class AppPolicyReviewInventoryTest {
    private val ownPackage = "org.privacage.android"

    @Test
    fun excludesPrivaCageOnlyAfterAUsableLauncherInventoryIsConfirmed() {
        assertEquals(
            setOf("org.example.reader", "org.example.notes"),
            AppPolicyReviewMonitor.validateLauncherInventory(
                setOf(ownPackage, "org.example.reader", "org.example.notes"),
                ownPackage
            )
        )
    }

    @Test
    fun rejectsMissingSelfOrAnEmptyVisibleInventoryInsteadOfReturningMassRemovalEvidence() {
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewMonitor.validateLauncherInventory(
                setOf("org.example.reader"),
                ownPackage
            )
        }
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewMonitor.validateLauncherInventory(
                setOf(ownPackage),
                ownPackage
            )
        }
        assertThrows(java.io.IOException::class.java) {
            AppPolicyReviewMonitor.validateLauncherInventory(
                emptySet(),
                ownPackage
            )
        }
    }
}
