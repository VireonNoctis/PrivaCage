package org.privacage.android.sync

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class SyncReceiveTransactionTest {
    private val senderFingerprint = "ab".repeat(32)
    private val messageId = "cd".repeat(16)
    private val payload = """{"settings":{"theme":"monochrome"}}"""

    @Test
    fun journalCanBeRecoveredWithoutAdvancingCursorBeforeLedgerCommit() {
        val record = JSONObject().put("relay_cursor", 41L)

        SyncReceiveTransactionRecord.stage(
            record = record,
            currentCursor = 41L,
            relayCursor = 42L,
            messageId = messageId,
            senderFingerprint = senderFingerprint,
            payloadJson = payload
        )

        // A process kill here leaves only the encrypted journal; the public cursor
        // and pending-profile fields have not been advanced.
        val persisted = JSONObject(record.toString())
        assertEquals(41L, persisted.getLong("relay_cursor"))
        assertFalse(persisted.has("pending_profile_json"))
        assertFalse(persisted.has("pending_sender_fingerprint"))

        val recovered = SyncReceiveTransactionRecord.read(persisted, 41L)
        assertNotNull(recovered)
        SyncReceiveTransactionRecord.commit(persisted, recovered!!)

        assertEquals(42L, persisted.getLong("relay_cursor"))
        assertEquals(payload, persisted.getString("pending_profile_json"))
        assertEquals(senderFingerprint, persisted.getString("pending_sender_fingerprint"))
        assertFalse(persisted.has(SyncReceiveTransactionRecord.KEY))
        assertNull(SyncReceiveTransactionRecord.read(persisted, 42L))
    }

    @Test
    fun refusesStaleCursorAndAlreadyPendingProfile() {
        val stale = JSONObject().put("relay_cursor", 9L)
        assertThrows(IOException::class.java) {
            SyncReceiveTransactionRecord.stage(
                stale, 9L, 9L, messageId, senderFingerprint, payload
            )
        }

        val occupied = JSONObject()
            .put("relay_cursor", 9L)
            .put("pending_profile_json", """{"existing":true}""")
        assertThrows(IOException::class.java) {
            SyncReceiveTransactionRecord.stage(
                occupied, 9L, 10L, messageId, senderFingerprint, payload
            )
        }
    }

    @Test
    fun rejectsMalformedJournalAndUnknownFields() {
        val malformed = JSONObject()
            .put("relay_cursor", 1L)
            .put(
                SyncReceiveTransactionRecord.KEY,
                JSONObject()
                    .put("message_id", messageId)
                    .put("cursor", 2L)
                    .put("sender_fingerprint", senderFingerprint)
                    .put("payload_json", payload)
                    .put("untrusted", true)
            )
        assertThrows(IOException::class.java) {
            SyncReceiveTransactionRecord.read(malformed, 1L)
        }

        val duplicatePayload = JSONObject()
            .put("relay_cursor", 1L)
            .put(
                SyncReceiveTransactionRecord.KEY,
                JSONObject()
                    .put("message_id", messageId)
                    .put("cursor", 2L)
                    .put("sender_fingerprint", senderFingerprint)
                    .put("payload_json", """{"x":1,"x":2}""")
            )
        assertThrows(IOException::class.java) {
            SyncReceiveTransactionRecord.read(duplicatePayload, 1L)
        }
    }

    @Test
    fun refusesCommitWhenJournalChanged() {
        val record = JSONObject().put("relay_cursor", 1L)
        SyncReceiveTransactionRecord.stage(
            record, 1L, 2L, messageId, senderFingerprint, payload
        )
        val transaction = SyncReceiveTransactionRecord.read(record, 1L)!!
        record.getJSONObject(SyncReceiveTransactionRecord.KEY).put("payload_json", """{"changed":true}""")

        assertThrows(IOException::class.java) {
            SyncReceiveTransactionRecord.commit(record, transaction)
        }
        assertTrue(record.has(SyncReceiveTransactionRecord.KEY))
        assertEquals(1L, record.getLong("relay_cursor"))
    }
}
