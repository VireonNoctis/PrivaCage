package org.privacage.android.sync

import org.json.JSONObject
import java.io.IOException

internal data class PendingPeerKeyRotation(
    val previousFingerprint: String,
    val nextCard: JSONObject,
    val rotation: JSONObject,
    val nextBundleBase64: String,
    val nextLocalPassphrase: String,
    val stagedAtUnix: Long
)

/**
 * Strict persisted state for a non-owner peer-key rotation.
 *
 * The old identity remains active while this record is present. Activation only
 * happens after an owner-signed roster authorizes the replacement card, and the
 * caller saves the whole updated identity record in one atomic encrypted write.
 */
internal object SyncPeerKeyRotationRecord {
    const val KEY = "pending_key_rotation"

    private const val KEY_BUNDLE = "identity_bundle_base64"
    private const val KEY_LOCAL_PASSPHRASE = "local_passphrase"
    private const val KEY_CARD = "card_json"
    private const val KEY_NEXT_SEQUENCE = "next_sequence"

    private val FIELDS = setOf(
        "previous_fingerprint",
        "next_card",
        "rotation_json",
        "next_bundle_base64",
        "next_local_passphrase",
        "staged_at_unix"
    )

    @Throws(IOException::class)
    fun create(
        previousFingerprint: String,
        nextCard: JSONObject,
        rotation: JSONObject,
        nextBundleBase64: String,
        nextLocalPassphrase: String,
        stagedAtUnix: Long
    ): JSONObject {
        val value = JSONObject()
            .put("previous_fingerprint", previousFingerprint)
            .put("next_card", nextCard)
            .put("rotation_json", rotation)
            .put("next_bundle_base64", nextBundleBase64)
            .put("next_local_passphrase", nextLocalPassphrase)
            .put("staged_at_unix", stagedAtUnix)
        read(JSONObject().put(KEY, value), previousFingerprint)
            ?: throw IOException("Staged peer-key rotation could not be validated.")
        return value
    }

    @Throws(IOException::class)
    fun read(record: JSONObject, activeFingerprint: String): PendingPeerKeyRotation? {
        if (!record.has(KEY)) return null
        val value = record.optJSONObject(KEY)
            ?: throw IOException("Staged key rotation is malformed.")
        val actual = mutableSetOf<String>()
        val keys = value.keys()
        while (keys.hasNext()) actual += keys.next()
        if (actual != FIELDS) {
            throw IOException("Staged key rotation has unsupported or missing fields.")
        }

        val previousFingerprint = value.opt("previous_fingerprint") as? String
            ?: throw IOException("Staged key rotation predecessor fingerprint is invalid.")
        validate(previousFingerprint, activeFingerprint)

        val nextCard = value.optJSONObject("next_card")
            ?: throw IOException("Staged key rotation omitted its replacement card.")
        val rotation = value.optJSONObject("rotation_json")
            ?: throw IOException("Staged key rotation omitted its signed transition.")
        val nextBundle = value.opt("next_bundle_base64") as? String
            ?: throw IOException("Staged key rotation replacement bundle is invalid.")
        val nextPassphrase = value.opt("next_local_passphrase") as? String
            ?: throw IOException("Staged key rotation replacement passphrase is invalid.")
        if (nextBundle.isBlank() || nextBundle.length > 1_500_000 ||
            nextPassphrase.isBlank() || nextPassphrase.length > 1024
        ) {
            throw IOException("Staged key rotation replacement identity is incomplete or oversized.")
        }
        val nextFingerprint = nextCard.opt("fingerprint_sha256") as? String
            ?: throw IOException("Staged key rotation replacement fingerprint is invalid.")
        if (!validFingerprint(nextFingerprint) || nextFingerprint == previousFingerprint) {
            throw IOException("Staged key rotation replacement card is not a different valid identity.")
        }
        val stagedAt = exactLong(value.opt("staged_at_unix"), "Staged key-rotation timestamp")
        if (stagedAt <= 0L) throw IOException("Staged key-rotation timestamp is invalid.")

        return PendingPeerKeyRotation(
            previousFingerprint,
            nextCard,
            rotation,
            nextBundle,
            nextPassphrase,
            stagedAt
        )
    }

    /**
     * Applies the replacement fields to the in-memory record after the signed roster
     * and replacement private bundle have both been independently verified.
     * The caller must persist this candidate record atomically before reporting success.
     */
    @Throws(IOException::class)
    fun activate(record: JSONObject, activeFingerprint: String): PendingPeerKeyRotation {
        val pending = read(record, activeFingerprint)
            ?: throw IOException("No staged peer-key rotation is available to activate.")
        val activeCard = try {
            JSONObject(record.getString(KEY_CARD))
        } catch (exception: Exception) {
            throw IOException("Current identity card is missing during key activation.", exception)
        }
        if (activeCard.optString("fingerprint_sha256") != activeFingerprint) {
            throw IOException("Current identity changed before the staged key rotation could activate.")
        }

        record.put(KEY_BUNDLE, pending.nextBundleBase64)
        record.put(KEY_LOCAL_PASSPHRASE, pending.nextLocalPassphrase)
        record.put(KEY_CARD, pending.nextCard.toString())
        record.put(KEY_NEXT_SEQUENCE, 1L)
        record.remove(KEY)
        return pending
    }

    private fun validate(previousFingerprint: String, activeFingerprint: String) {
        if (!validFingerprint(previousFingerprint) || previousFingerprint != activeFingerprint) {
            throw IOException("Staged key rotation predecessor does not match the active identity.")
        }
    }

    private fun validFingerprint(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

    private fun exactLong(value: Any?, label: String): Long = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> throw IOException("$label must be an exact integer.")
    }
}
