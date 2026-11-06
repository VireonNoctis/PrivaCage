package org.privacage.android.sync

import org.json.JSONObject
import org.privacage.android.StrictJsonKeyScanner
import java.io.IOException
import java.nio.charset.StandardCharsets

internal data class PendingSyncReceiveTransaction(
    val messageId: String,
    val relayCursor: Long,
    val senderFingerprint: String,
    val payloadJson: String
)

/**
 * Journal format for the Android sync receive two-phase commit.
 *
 * The journal lives in the Keystore-encrypted identity record. It is persisted before
 * the separate replay ledger is touched, so a restart can safely retry replay registration.
 */
internal object SyncReceiveTransactionRecord {
    const val KEY = "pending_receive_transaction"

    private const val KEY_CURSOR = "relay_cursor"
    private const val KEY_PENDING_PROFILE = "pending_profile_json"
    private const val KEY_PENDING_SENDER = "pending_sender_fingerprint"
    private const val MAX_PROFILE_BYTES = 1_048_576

    private val TRANSACTION_KEYS = setOf(
        "message_id",
        "cursor",
        "sender_fingerprint",
        "payload_json"
    )

    @Throws(IOException::class)
    fun stage(
        record: JSONObject,
        currentCursor: Long,
        relayCursor: Long,
        messageId: String,
        senderFingerprint: String,
        payloadJson: String
    ) {
        if (record.has(KEY)) {
            throw IOException("A sync receive transaction is already pending recovery.")
        }
        if (record.has(KEY_PENDING_PROFILE) || record.has(KEY_PENDING_SENDER)) {
            throw IOException("A received profile is already waiting for user review.")
        }
        val storedCursor = exactLong(record.opt(KEY_CURSOR) ?: 0L, "Stored relay cursor")
        if (storedCursor != currentCursor || relayCursor <= currentCursor) {
            throw IOException("Sync receive cursor changed before the packet could be staged.")
        }
        record.put(
            KEY,
            JSONObject()
                .put("message_id", messageId)
                .put("cursor", relayCursor)
                .put("sender_fingerprint", senderFingerprint)
                .put("payload_json", payloadJson)
        )
        read(record, currentCursor)
            ?: throw IOException("Sync receive transaction could not be verified after staging.")
    }

    @Throws(IOException::class)
    fun read(record: JSONObject, currentCursor: Long): PendingSyncReceiveTransaction? {
        if (!record.has(KEY)) return null
        val value = record.optJSONObject(KEY)
            ?: throw IOException("Pending sync receive transaction is malformed.")
        val actualKeys = mutableSetOf<String>()
        val iterator = value.keys()
        while (iterator.hasNext()) actualKeys += iterator.next()
        if (actualKeys != TRANSACTION_KEYS) {
            throw IOException("Pending sync receive transaction has unsupported or missing fields.")
        }

        val messageId = value.opt("message_id") as? String
            ?: throw IOException("Pending sync receive message ID is invalid.")
        if (messageId.length != 32 || messageId.any { it !in '0'..'9' && it !in 'a'..'f' }) {
            throw IOException("Pending sync receive message ID is not canonical lowercase hex.")
        }
        val relayCursor = exactLong(value.opt("cursor"), "Pending relay cursor")
        if (relayCursor <= currentCursor) {
            throw IOException("Pending sync receive cursor does not advance the saved cursor.")
        }
        val sender = value.opt("sender_fingerprint") as? String
            ?: throw IOException("Pending sync sender fingerprint is invalid.")
        if (sender.length != 64 || sender.any { it !in '0'..'9' && it !in 'a'..'f' }) {
            throw IOException("Pending sync sender fingerprint is not a full lowercase SHA-256 digest.")
        }
        val payloadJson = value.opt("payload_json") as? String
            ?: throw IOException("Pending sync profile payload is invalid.")
        if (payloadJson.toByteArray(StandardCharsets.UTF_8).size !in 2..MAX_PROFILE_BYTES) {
            throw IOException("Pending sync profile payload exceeds the supported size.")
        }
        try {
            StrictJsonKeyScanner.validate(payloadJson, "Pending sync profile")
            JSONObject(payloadJson)
        } catch (exception: Exception) {
            throw IOException("Pending sync profile is malformed or ambiguous.", exception)
        }
        return PendingSyncReceiveTransaction(messageId, relayCursor, sender, payloadJson)
    }

    @Throws(IOException::class)
    fun commit(record: JSONObject, transaction: PendingSyncReceiveTransaction) {
        val currentCursor = exactLong(record.opt(KEY_CURSOR) ?: 0L, "Stored relay cursor")
        val persisted = read(record, currentCursor)
            ?: throw IOException("Pending sync receive transaction is missing.")
        if (persisted != transaction) {
            throw IOException("Pending sync receive transaction changed before it could be committed.")
        }
        record.put(KEY_CURSOR, transaction.relayCursor)
        record.put(KEY_PENDING_PROFILE, transaction.payloadJson)
        record.put(KEY_PENDING_SENDER, transaction.senderFingerprint)
        record.remove(KEY)
    }

    private fun exactLong(value: Any?, label: String): Long = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> throw IOException("$label must be an exact integer.")
    }
}
