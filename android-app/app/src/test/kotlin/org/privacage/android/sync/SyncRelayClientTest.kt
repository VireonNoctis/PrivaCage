package org.privacage.android.sync

import org.json.JSONObject
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
    fun memberRevocationPolicyRecognizesActiveAndAlreadyRevokedMembers() {
        val fingerprint = "a".repeat(64)
        val active = listOf(RelayMemberEntry(fingerprint, null))
        assertFalse(
            SyncRelayClient.evaluateMemberRevocationState(true, active, fingerprint).alreadyRevoked
        )

        val revoked = listOf(RelayMemberEntry(fingerprint, 200L))
        assertTrue(
            SyncRelayClient.evaluateMemberRevocationState(true, revoked, fingerprint).alreadyRevoked
        )
    }

    @Test
    fun memberRevocationPolicyFailsClosedForLegacyModeUnknownTargetsAndMalformedState() {
        val fingerprint = "a".repeat(64)
        assertIoFails {
            SyncRelayClient.evaluateMemberRevocationState(
                false, listOf(RelayMemberEntry(fingerprint, null)), fingerprint
            )
        }
        assertIoFails {
            SyncRelayClient.evaluateMemberRevocationState(true, emptyList(), fingerprint)
        }
        assertIoFails {
            SyncRelayClient.evaluateMemberRevocationState(
                true, listOf(RelayMemberEntry(fingerprint, 0L)), fingerprint
            )
        }
        assertIoFails {
            SyncRelayClient.evaluateMemberRevocationState(
                true, listOf(RelayMemberEntry("BAD", null)), fingerprint
            )
        }
        assertIoFails {
            SyncRelayClient.evaluateMemberRevocationState(
                true,
                listOf(RelayMemberEntry(fingerprint, null), RelayMemberEntry(fingerprint, 100L)),
                fingerprint
            )
        }
    }

    @Test
    fun rejectsDuplicateMemberModeInRelayAdminResponse() {
        assertIoFails {
            SyncRelayClient.parseMemberRevocationState(
                """{"member_mode":true,"member_mode":false,"members":[]}""",
                "a".repeat(64)
            )
        }
    }

    @Test
    fun rejectsEscapedEquivalentDuplicateKeysInNestedRelayedObjects() {
        assertIoFails {
            SyncRelayClient.parseMemberRevocationState(
                """{"member_mode":true,"members":[{"fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","revoked_at_unix":null,"revoked_at_\u0075nix":1}]}""",
                "a".repeat(64)
            )
        }
    }

    @Test
    fun uploadRejectsAmbiguousPacketBeforeOpeningNetworkConnection() {
        val client = SyncRelayClient(
            "https://sync.example.org",
            "device-space_0001",
            "a".repeat(64),
            "b".repeat(64)
        ) { _, _, _, _, _ -> "signature" }

        assertIoFails {
            client.upload(
                "c".repeat(32),
                """{"body":{"header":{"message_id":"${"c".repeat(32)}","message_id":"d"}}}"""
            )
        }
    }

    @Test
    fun relayMetadataReadersRejectStringBooleanAndFractionalCoercions() {
        assertEquals(5L, requireRelayLong(JSONObject("""{"cursor":5}"""), "cursor", "test"))
        assertIoFails { requireRelayLong(JSONObject("""{"cursor":"5"}"""), "cursor", "test") }
        assertIoFails { requireRelayLong(JSONObject("""{"cursor":5.0}"""), "cursor", "test") }
        assertIoFails { requireRelayLong(JSONObject("""{"cursor":true}"""), "cursor", "test") }

        assertEquals("msg-1", requireRelayString(JSONObject("""{"message_id":"msg-1"}"""), "message_id", "test"))
        assertIoFails { requireRelayString(JSONObject("""{"message_id":123}"""), "message_id", "test") }

        assertEquals(true, requireRelayBoolean(JSONObject("""{"member_mode":true}"""), "member_mode", "test"))
        assertIoFails { requireRelayBoolean(JSONObject("""{"member_mode":"true"}"""), "member_mode", "test") }
    }

    @Test
    fun memberRevocationParserRejectsCoercibleFieldTypes() {
        val fingerprint = "a".repeat(64)
        val stringMode = """{"member_mode":"true","members":[{"fingerprint":"${fingerprint}","revoked_at_unix":null}]}"""
        assertIoFails { SyncRelayClient.parseMemberRevocationState(stringMode, fingerprint) }

        val stringTimestamp = """{"member_mode":true,"members":[{"fingerprint":"${fingerprint}","revoked_at_unix":"200"}]}"""
        assertIoFails { SyncRelayClient.parseMemberRevocationState(stringTimestamp, fingerprint) }

        val numericFingerprint = """{"member_mode":true,"members":[{"fingerprint":123,"revoked_at_unix":null}]}"""
        assertIoFails { SyncRelayClient.parseMemberRevocationState(numericFingerprint, fingerprint) }
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
