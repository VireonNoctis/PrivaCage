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

    private fun assertFails(operation: () -> Unit) {
        try {
            operation()
            throw AssertionError("Expected validation to reject this value.")
        } catch (_: IllegalArgumentException) {
            // Expected validation failure.
        }
    }
}
