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

class SyncPeerKeyRotationRecordTest {
    private val previousFingerprint = "ab".repeat(32)
    private val nextFingerprint = "cd".repeat(32)
    private val previousCard = JSONObject().put("fingerprint_sha256", previousFingerprint)
    private val nextCard = JSONObject().put("fingerprint_sha256", nextFingerprint)
    private val rotation = JSONObject().put("signature_hex", "01".repeat(64))

    private fun stagedRecord(): JSONObject {
        val record = JSONObject()
            .put("identity_bundle_base64", "old-bundle")
            .put("local_passphrase", "old-passphrase")
            .put("card_json", previousCard.toString())
            .put("next_sequence", 9L)
        record.put(
            SyncPeerKeyRotationRecord.KEY,
            SyncPeerKeyRotationRecord.create(
                previousFingerprint,
                nextCard,
                rotation,
                "new-bundle",
                "new-passphrase",
                1_800_000_000L
            )
        )
        return record
    }

    @Test
    fun stagedRotationSurvivesReloadWithoutReplacingTheActiveIdentity() {
        val reloaded = JSONObject(stagedRecord().toString())
        val pending = SyncPeerKeyRotationRecord.read(reloaded, previousFingerprint)

        assertNotNull(pending)
        assertEquals(previousFingerprint, pending!!.previousFingerprint)
        assertEquals(nextFingerprint, pending.nextCard.getString("fingerprint_sha256"))
        assertEquals(previousFingerprint, JSONObject(reloaded.getString("card_json")).getString("fingerprint_sha256"))
        assertEquals("old-bundle", reloaded.getString("identity_bundle_base64"))
        assertTrue(reloaded.has(SyncPeerKeyRotationRecord.KEY))
    }

    @Test
    fun activationChangesIdentityAndClearsStageInOneCandidateRecord() {
        val original = stagedRecord()
        val candidate = JSONObject(original.toString())

        val activated = SyncPeerKeyRotationRecord.activate(candidate, previousFingerprint)

        assertEquals(previousFingerprint, activated.previousFingerprint)
        assertEquals(nextFingerprint, JSONObject(candidate.getString("card_json")).getString("fingerprint_sha256"))
        assertEquals("new-bundle", candidate.getString("identity_bundle_base64"))
        assertEquals("new-passphrase", candidate.getString("local_passphrase"))
        assertEquals(1L, candidate.getLong("next_sequence"))
        assertFalse(candidate.has(SyncPeerKeyRotationRecord.KEY))

        // If the final encrypted-record write fails, the original persisted candidate
        // remains staged with the previous identity and can be retried after restart.
        assertEquals(previousFingerprint, JSONObject(original.getString("card_json")).getString("fingerprint_sha256"))
        assertTrue(original.has(SyncPeerKeyRotationRecord.KEY))
    }

    @Test
    fun rejectsMismatchedPredecessorAndUnknownNestedFields() {
        val record = stagedRecord()
        assertThrows(IOException::class.java) {
            SyncPeerKeyRotationRecord.read(record, nextFingerprint)
        }

        record.getJSONObject(SyncPeerKeyRotationRecord.KEY).put("unexpected", true)
        assertThrows(IOException::class.java) {
            SyncPeerKeyRotationRecord.read(record, previousFingerprint)
        }
    }

    @Test
    fun rejectsMalformedTimestampAndMissingReplacementMaterial() {
        val badTime = stagedRecord()
        badTime.getJSONObject(SyncPeerKeyRotationRecord.KEY).put("staged_at_unix", "1800000000")
        assertThrows(IOException::class.java) {
            SyncPeerKeyRotationRecord.read(badTime, previousFingerprint)
        }

        val missingBundle = stagedRecord()
        missingBundle.getJSONObject(SyncPeerKeyRotationRecord.KEY).put("next_bundle_base64", "")
        assertThrows(IOException::class.java) {
            SyncPeerKeyRotationRecord.read(missingBundle, previousFingerprint)
        }
    }

    @Test
    fun noStageIsNotTreatedAsAnActivation() {
        val record = JSONObject().put("card_json", previousCard.toString())
        assertNull(SyncPeerKeyRotationRecord.read(record, previousFingerprint))
        assertThrows(IOException::class.java) {
            SyncPeerKeyRotationRecord.activate(record, previousFingerprint)
        }
    }
}
