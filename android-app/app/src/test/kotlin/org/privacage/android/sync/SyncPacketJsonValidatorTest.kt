package org.privacage.android.sync

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SyncPacketJsonValidatorTest {
    @Test
    fun acceptsBoundedSyntacticallyValidPacketForCryptographicVerification() {
        val packet = SyncPacketJsonValidator.parse(
            """{"body":{"header":{"message_id":"msg-1","sender_fingerprint_sha256":"${"a".repeat(64)}"},"ciphertext":"AA=="},"signature":"test-only"}"""
        )

        assertEquals("msg-1", packet.getJSONObject("body").getJSONObject("header").getString("message_id"))
    }

    @Test
    fun rejectsDuplicateTopLevelAndNestedKeysBeforeJSONObjectCanCollapseThem() {
        assertThrows(IOException::class.java) {
            SyncPacketJsonValidator.parse("""{"body":{},"body":{}}""")
        }
        assertThrows(IOException::class.java) {
            SyncPacketJsonValidator.parse("""{"body":{"header":{"message_id":"first","message_id":"second"}}}""")
        }
    }

    @Test
    fun rejectsEscapedEquivalentDuplicateHeaderKeys() {
        val packet = """{"body":{"header":{"message_id":"first","message_\u0069d":"second"}}}"""
        val exception = assertThrows(IOException::class.java) {
            SyncPacketJsonValidator.parse(packet)
        }
        assertTrue(exception.message.orEmpty().contains("duplicate"))
    }

    @Test
    fun rejectsMalformedJsonNonObjectRootsAndOversizedPayloads() {
        assertThrows(IOException::class.java) {
            SyncPacketJsonValidator.parse("""{"body": tru}""")
        }
        assertThrows(IOException::class.java) {
            SyncPacketJsonValidator.parse("""[]""")
        }
        assertThrows(IOException::class.java) {
            SyncPacketJsonValidator.parse(" ".repeat(SyncPacketJsonValidator.MAX_PACKET_JSON_BYTES + 1))
        }
    }
}
