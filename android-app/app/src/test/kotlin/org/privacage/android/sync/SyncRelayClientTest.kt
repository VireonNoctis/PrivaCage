package org.privacage.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SyncRelayClientTest {
    @Test
    fun acceptsHttpsRelayUrlsAndRemovesTrailingSlash() {
        assertEquals("https://sync.example.org", SyncRelayClient.validateBaseUrl("https://sync.example.org/"))
        assertEquals("https://example.org/relay", SyncRelayClient.validateBaseUrl("https://example.org/relay/"))
    }

    @Test
    fun acceptsOnlyPrintableWhitespaceFreeAdminTokens() {
        assertTrue(SyncRelayClient.isValidAdminToken("a".repeat(32)))
        assertTrue(SyncRelayClient.isValidAdminToken("A1-_".repeat(16)))
        assertFalse(SyncRelayClient.isValidAdminToken("a".repeat(31)))
        assertFalse(SyncRelayClient.isValidAdminToken("a".repeat(32) + " "))
        assertFalse(SyncRelayClient.isValidAdminToken("a".repeat(32) + "\n"))
    }

    @Test
    fun memberRevocationParserRequiresActiveModeAndKnownTarget() {
        val fingerprint = "a".repeat(64)
        val active = """{"member_mode":true,"members":[{"fingerprint":"$fingerprint","created_at_unix":100,"revoked_at_unix":null}]}"""
        assertFalse(SyncRelayClient.parseMemberRevocationState(active, fingerprint).alreadyRevoked)

        val revoked = """{"member_mode":true,"members":[{"fingerprint":"$fingerprint","created_at_unix":100,"revoked_at_unix":200}]}"""
        assertTrue(SyncRelayClient.parseMemberRevocationState(revoked, fingerprint).alreadyRevoked)
    }

    @Test
    fun memberRevocationParserFailsClosedForLegacyModeUnknownTargetsAndMalformedState() {
        val fingerprint = "a".repeat(64)
        assertIoFails {
            SyncRelayClient.parseMemberRevocationState(
                """{"member_mode":false,"members":[{"fingerprint":"$fingerprint","revoked_at_unix":null}]}""",
                fingerprint
            )
        }
        assertIoFails {
            SyncRelayClient.parseMemberRevocationState(
                """{"member_mode":true,"members":[]}""",
                fingerprint
            )
        }
        assertIoFails {
            SyncRelayClient.parseMemberRevocationState("{bad-json", fingerprint)
        }
        assertIoFails {
            SyncRelayClient.parseMemberRevocationState(
                """{"member_mode":true,"members":[{"fingerprint":"$fingerprint","revoked_at_unix":0}]}""",
                fingerprint
            )
        }
    }

    @Test
    fun rejectsPlainHttpAndCredentialBearingUrls() {
        assertFails { SyncRelayClient.validateBaseUrl("http://sync.example.org") }
        assertFails { SyncRelayClient.validateBaseUrl("https://user:secret@sync.example.org") }
        assertFails { SyncRelayClient.validateBaseUrl("https://sync.example.org?token=secret") }
        assertFails { SyncRelayClient.validateBaseUrl("https://sync.example.org/#fragment") }
    }

    @Test
    fun checksRelayCapabilityAndSpaceIdentifierStrictly() {
        assertTrue(SyncRelayClient.isValidSpaceId("device-space_0001"))
        assertFalse(SyncRelayClient.isValidSpaceId("short"))
        assertFalse(SyncRelayClient.isValidSpaceId("bad space-id"))
        assertTrue(SyncRelayClient.isValidCapability("0123456789abcdef".repeat(4)))
        assertFalse(SyncRelayClient.isValidCapability("ABCDEF".repeat(10) + "abcd"))
        assertFalse(SyncRelayClient.isValidCapability("f".repeat(63)))
    }

    private fun assertIoFails(operation: () -> Unit) {
        try {
            operation()
            throw AssertionError("Expected validation to reject this value.")
        } catch (_: java.io.IOException) {
            // Expected fail-closed rejection.
        }
    }

    private fun assertFails(operation: () -> Unit) {
        try {
            operation()
            throw AssertionError("Expected validation to reject this value.")
        } catch (_: IllegalArgumentException) {
            // Expected validation failure.
        }
    }
}
