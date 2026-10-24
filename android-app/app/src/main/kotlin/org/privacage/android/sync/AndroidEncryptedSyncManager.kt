package org.privacage.android.sync

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

internal class SyncBridgeFailure(message: String) : IOException(message)
internal data class SyncReceiveResult(
    val status: String,
    val message: String,
    val profileJson: String? = null,
    val senderFingerprint: String? = null
)

/**
 * Android orchestration around the shared Rust protocol and HTTPS-only opaque relay.
 * Peer cards are never auto-trusted, and received settings require explicit user approval.
 */
internal class AndroidEncryptedSyncManager(context: Context) {
    private val appContext = context.applicationContext
    private val store = AndroidKeystoreIdentityStore(appContext)
    private val bridge by lazy { NativeSyncBridge() }

    @Synchronized
    @Throws(IOException::class)
    fun createIdentity(): JSONObject {
        val existing = store.loadRecord()
        if (existing != null) {
            validateLocalRecord(existing)
            return JSONObject(existing.getString(KEY_CARD_JSON))
        }
        val localPassphrase = randomLocalPassphrase()
        val response = parseNative(bridge.nativeCreateIdentity(localPassphrase))
        val card = response.getJSONObject("card")
        val record = newRecord(
            localPassphrase,
            response.getString("recovery_bundle_base64"),
            card.toString()
        )
        store.saveRecord(record)
        return card
    }

    @Synchronized
    @Throws(IOException::class)
    fun localCardJson(): String {
        val record = requireRecord()
        validateLocalRecord(record)
        return record.getString(KEY_CARD_JSON)
    }

    @Synchronized
    @Throws(IOException::class)
    fun verifyPeerCard(cardJson: String): JSONObject {
        if (cardJson.isBlank() || cardJson.length > MAX_CARD_JSON_BYTES) {
            throw IOException("Paste a complete public device card under 32 KiB.")
        }
        return parseNative(bridge.nativeVerifyIdentityCard(cardJson)).getJSONObject("card")
    }

    @Synchronized
    @Throws(IOException::class)
    fun trustPeerCard(cardJson: String, independentlyConfirmedFingerprint: String): String {
        val record = requireRecord()
        validateLocalRecord(record)
        val verified = parseNative(bridge.nativeVerifyIdentityCard(cardJson))
        val card = verified.getJSONObject("card")
        val fingerprint = verified.getString("fingerprint_sha256")
        if (independentlyConfirmedFingerprint.trim().lowercase() != fingerprint) {
            throw IOException("Independent fingerprint confirmation did not match; the device was not trusted.")
        }
        val localFingerprint = JSONObject(record.getString(KEY_CARD_JSON)).getString("fingerprint_sha256")
        if (fingerprint == localFingerprint) throw IOException("This is your own device card; it cannot be added as a peer.")
        val trusted = record.optJSONObject(KEY_TRUSTED_CARDS) ?: JSONObject()
        if (!trusted.has(fingerprint) && trusted.length() >= MAX_TRUSTED_CARDS) {
            throw IOException("The trusted-device list reached its limit of " + MAX_TRUSTED_CARDS + " devices.")
        }
        trusted.put(fingerprint, card)
        record.put(KEY_TRUSTED_CARDS, trusted)
        // Re-trust is possible only after the caller confirms the full fingerprint again.
        val revoked = record.optJSONObject(KEY_REVOKED_FINGERPRINTS) ?: JSONObject()
        revoked.remove(fingerprint)
        record.put(KEY_REVOKED_FINGERPRINTS, revoked)
        store.saveRecord(record)
        return fingerprint
    }

    @Synchronized
    @Throws(IOException::class)
    fun listTrustedPeers(): org.json.JSONArray {
        val record = requireRecord()
        validateLocalRecord(record)
        val trusted = record.optJSONObject(KEY_TRUSTED_CARDS) ?: JSONObject()
        val fingerprints = mutableListOf<String>()
        val keys = trusted.keys()
        while (keys.hasNext()) fingerprints += keys.next()
        val result = org.json.JSONArray()
        fingerprints.sorted().forEach { fingerprint ->
            val card = trusted.optJSONObject(fingerprint) ?: return@forEach
            result.put(
                JSONObject()
                    .put("fingerprint_sha256", fingerprint)
                    .put("device_id", card.optString("device_id"))
                    .put("key_epoch", card.optLong("key_epoch", 0L))
            )
        }
        return result
    }

    @Synchronized
    @Throws(IOException::class)
    fun revokeTrustedPeer(fingerprint: String): String {
        if (fingerprint.length != 64 || fingerprint.any { it !in '0'..'9' && it !in 'a'..'f' }) {
            throw IOException("Peer fingerprint must be a full lowercase SHA-256 hex digest.")
        }
        val record = requireRecord()
        val trusted = record.optJSONObject(KEY_TRUSTED_CARDS) ?: JSONObject()
        if (!trusted.has(fingerprint)) {
            throw IOException("This fingerprint is not currently trusted on this device.")
        }
        trusted.remove(fingerprint)
        record.put(KEY_TRUSTED_CARDS, trusted)

        // Keep a denylist so old cards cannot be silently re-trusted via a future code path.
        // Explicit trust confirmation removes this tombstone only after the complete fingerprint is re-entered.
        val revoked = record.optJSONObject(KEY_REVOKED_FINGERPRINTS) ?: JSONObject()
        revoked.put(fingerprint, System.currentTimeMillis() / 1000L)
        record.put(KEY_REVOKED_FINGERPRINTS, revoked)

        // A received-but-not-yet-applied profile from the revoked peer must not remain approvable.
        if (record.optString(KEY_PENDING_SENDER, "") == fingerprint) {
            record.remove(KEY_PENDING_PROFILE)
            record.remove(KEY_PENDING_SENDER)
        }
        store.saveRecord(record)
        return fingerprint
    }

    @Synchronized
    @Throws(IOException::class)
    fun saveRelayConfiguration(baseUrl: String, spaceId: String, capability: String) {
        val normalizedUrl = try {
            SyncRelayClient.validateBaseUrl(baseUrl)
        } catch (exception: IllegalArgumentException) {
            throw IOException(exception.message ?: "Relay URL is invalid.", exception)
        }
        if (!SyncRelayClient.isValidSpaceId(spaceId)) {
            throw IOException("Space ID must be 8–80 ASCII letters, digits, underscores, or hyphens.")
        }
        if (!SyncRelayClient.isValidCapability(capability)) {
            throw IOException("Space capability must be 64 lowercase hexadecimal characters.")
        }
        val record = requireRecord()
        record.put(KEY_RELAY_URL, normalizedUrl)
        record.put(KEY_SPACE_ID, spaceId)
        record.put(KEY_CAPABILITY, capability)
        store.saveRecord(record)
    }

    @Synchronized
    @Throws(IOException::class)
    fun storedConfigurationForUi(): JSONObject? {
        val record = store.loadRecord() ?: return null
        return JSONObject()
            .put("relay_url", record.optString(KEY_RELAY_URL, ""))
            .put("space_id", record.optString(KEY_SPACE_ID, ""))
            .put("capability_token", record.optString(KEY_CAPABILITY, ""))
            .put("has_identity", record.has(KEY_CARD_JSON))
            .put("trusted_count", record.optJSONObject(KEY_TRUSTED_CARDS)?.length() ?: 0)
            .put("revoked_count", record.optJSONObject(KEY_REVOKED_FINGERPRINTS)?.length() ?: 0)
    }

    @Synchronized
    @Throws(IOException::class)
    fun sendProfile(profileJson: String, recipientCardJson: String): String {
        if (profileJson.isEmpty() || profileJson.toByteArray(StandardCharsets.UTF_8).size > MAX_PROFILE_BYTES) {
            throw IOException("Settings profile exceeds the supported size.")
        }
        val record = requireRecord()
        val localCard = JSONObject(record.getString(KEY_CARD_JSON))
        val verifiedReply = parseNative(bridge.nativeVerifyIdentityCard(recipientCardJson))
        val recipientCard = verifiedReply.getJSONObject("card")
        val fingerprint = verifiedReply.getString("fingerprint_sha256")
        val trustedCards = record.optJSONObject(KEY_TRUSTED_CARDS) ?: JSONObject()
        val trustedCard = trustedCards.optJSONObject(fingerprint)
            ?: throw IOException("This device is not trusted yet. Verify its fingerprint and explicitly trust it first.")
        if (trustedCard.optString("device_id") != recipientCard.optString("device_id") ||
            trustedCard.optString("fingerprint_sha256") != recipientCard.optString("fingerprint_sha256")
        ) {
            throw IOException("The pasted device card does not match the recorded trusted-device card.")
        }
        if (recipientCard.optString("device_id") == localCard.optString("device_id")) {
            throw IOException("Choose a different trusted recipient device.")
        }

        val sequence = record.optLong(KEY_NEXT_SEQUENCE, 1L)
        if (sequence < 1L || sequence == Long.MAX_VALUE) throw IOException("Local message sequence needs safe recovery.")
        record.put(KEY_NEXT_SEQUENCE, sequence + 1L)
        store.saveRecord(record)

        val now = System.currentTimeMillis() / 1000L
        val sealed = parseNative(
            bridge.nativeSealPacket(
                record.getString(KEY_BUNDLE_BASE64), record.getString(KEY_LOCAL_PASSPHRASE),
                recipientCard.toString(), profileJson, sequence, now, MESSAGE_TTL_SECONDS
            )
        )
        val packet = sealed.getJSONObject("packet")
        val messageId = sealed.getString("message_id")
        relayClient(record).upload(messageId, packet.toString())
        return "Encrypted settings packet sent to the trusted device. Message ID: " + messageId
    }

    @Synchronized
    @Throws(IOException::class)
    fun receiveProfile(validateProfile: (String) -> Unit): SyncReceiveResult {
        val record = requireRecord()
        val pending = record.optString(KEY_PENDING_PROFILE, "")
        if (pending.isNotEmpty()) {
            return SyncReceiveResult(
                "pending",
                "A previously received profile is waiting for your decision.",
                pending,
                record.optString(KEY_PENDING_SENDER, "")
            )
        }

        val localCard = JSONObject(record.getString(KEY_CARD_JSON))
        val localDeviceId = localCard.getString("device_id")
        val localFingerprint = localCard.getString("fingerprint_sha256")
        val trustedCards = record.optJSONObject(KEY_TRUSTED_CARDS) ?: JSONObject()
        var cursor = record.optLong(KEY_CURSOR, 0L)
        var skipped = 0

        repeat(MAX_MESSAGES_PER_CHECK) {
            val page = relayClient(record).fetchAfter(cursor, 1)
            val message = page.messages.firstOrNull()
                ?: return SyncReceiveResult(
                    "empty",
                    if (skipped == 0) "No new sync packets are available."
                    else "No applicable settings packet was found. Skipped " + skipped +
                        " invalid, replayed, or other-device packet(s)."
                )
            if (message.cursor <= cursor) throw IOException("Relay cursor did not advance.")
            val packet = try {
                JSONObject(message.packetJson)
            } catch (exception: Exception) {
                cursor = advanceCursor(record, message.cursor)
                skipped += 1
                return@repeat
            }
            val header = packet.optJSONObject("body")?.optJSONObject("header")
            if (header == null || header.optString("message_id") != message.messageId) {
                cursor = advanceCursor(record, message.cursor)
                skipped += 1
                return@repeat
            }
            if (header.optString("recipient_device_id") != localDeviceId ||
                header.optString("recipient_fingerprint_sha256") != localFingerprint
            ) {
                cursor = advanceCursor(record, message.cursor)
                return@repeat
            }

            val senderFingerprint = header.optString("sender_fingerprint_sha256")
            val revokedCards = record.optJSONObject(KEY_REVOKED_FINGERPRINTS) ?: JSONObject()
            if (revokedCards.has(senderFingerprint)) {
                // A revoked sender must not wedge the inbox cursor or keep a pending item visible.
                cursor = advanceCursor(record, message.cursor)
                skipped += 1
                return@repeat
            }
            val senderCard = trustedCards.optJSONObject(senderFingerprint)
                ?: return SyncReceiveResult(
                    "untrusted",
                    "A packet for this device came from an untrusted fingerprint. It remains queued. Verify and explicitly trust the sender card before retrying.",
                    senderFingerprint = senderFingerprint
                )
            val opened = try {
                parseNative(
                    bridge.nativeOpenPacket(
                        record.getString(KEY_BUNDLE_BASE64),
                        record.getString(KEY_LOCAL_PASSPHRASE),
                        senderCard.toString(),
                        message.packetJson,
                        System.currentTimeMillis() / 1000L,
                        File(appContext.filesDir, "$SYNC_DIRECTORY/replay-ledger.json").absolutePath
                    )
                )
            } catch (exception: SyncBridgeFailure) {
                val reason = exception.message.orEmpty()
                if (!reason.startsWith("packet_rejected:") && !reason.startsWith("replay:")) throw exception
                cursor = advanceCursor(record, message.cursor)
                skipped += 1
                return@repeat
            }

            val payloadJson = opened.optJSONObject("payload")?.toString()
            if (payloadJson == null) {
                cursor = advanceCursor(record, message.cursor)
                skipped += 1
                return@repeat
            }
            try {
                validateProfile(payloadJson)
            } catch (_: Exception) {
                cursor = advanceCursor(record, message.cursor)
                skipped += 1
                return@repeat
            }

            record.put(KEY_CURSOR, message.cursor)
            record.put(KEY_PENDING_PROFILE, payloadJson)
            record.put(KEY_PENDING_SENDER, senderFingerprint)
            store.saveRecord(record)
            return SyncReceiveResult(
                "pending",
                "A signed and encrypted settings profile was received. Review it before applying.",
                payloadJson,
                senderFingerprint
            )
        }

        return SyncReceiveResult(
            "scanned",
            "Checked " + MAX_MESSAGES_PER_CHECK + " queue item(s). " + skipped +
                " invalid or non-applicable item(s) were skipped. Check again to continue."
        )
    }

    @Synchronized
    @Throws(IOException::class)
    fun clearPendingProfile() {
        val record = requireRecord()
        record.remove(KEY_PENDING_PROFILE)
        record.remove(KEY_PENDING_SENDER)
        store.saveRecord(record)
    }

    @Synchronized
    @Throws(IOException::class)
    fun exportRecoveryBundle(recoveryPassphrase: String): ByteArray {
        requireRecoveryPassphrase(recoveryPassphrase)
        val record = requireRecord()
        val response = parseNative(
            bridge.nativeExportRecoveryBundle(
                record.getString(KEY_BUNDLE_BASE64),
                record.getString(KEY_LOCAL_PASSPHRASE),
                recoveryPassphrase
            )
        )
        return try {
            Base64.decode(response.getString("recovery_bundle_base64"), Base64.NO_WRAP)
        } catch (exception: Exception) {
            throw IOException("Native sync bridge returned an invalid recovery bundle.", exception)
        }
    }

    @Synchronized
    @Throws(IOException::class)
    fun prepareRecoveryImport(recoveryBundle: ByteArray, recoveryPassphrase: String): JSONObject {
        requireRecoveryPassphrase(recoveryPassphrase)
        if (recoveryBundle.isEmpty() || recoveryBundle.size > MAX_RECOVERY_BUNDLE_BYTES) {
            throw IOException("Recovery bundle is empty or exceeds the supported size.")
        }
        val localPassphrase = randomLocalPassphrase()
        val response = parseNative(
            bridge.nativeImportRecoveryBundle(
                Base64.encodeToString(recoveryBundle, Base64.NO_WRAP),
                recoveryPassphrase,
                localPassphrase
            )
        )
        return newRecord(
            localPassphrase,
            response.getString("recovery_bundle_base64"),
            response.getJSONObject("card").toString()
        )
    }

    @Synchronized
    @Throws(IOException::class)
    fun commitRecoveryImport(importedRecord: JSONObject) {
        // Recovery import begins with a clean local trust/configuration state.
        store.saveRecord(importedRecord, replaceMissingKeystoreKey = true)
    }

    private fun relayClient(record: JSONObject): SyncRelayClient {
        val url = record.optString(KEY_RELAY_URL, "")
        val space = record.optString(KEY_SPACE_ID, "")
        val capability = record.optString(KEY_CAPABILITY, "")
        if (url.isBlank() || space.isBlank() || capability.isBlank()) {
            throw IOException("Save a valid HTTPS relay URL, space ID and capability first.")
        }
        return try {
            SyncRelayClient(url, space, capability)
        } catch (exception: IllegalArgumentException) {
            throw IOException(exception.message ?: "Relay configuration is invalid.", exception)
        }
    }

    private fun advanceCursor(record: JSONObject, newCursor: Long): Long {
        record.put(KEY_CURSOR, newCursor)
        store.saveRecord(record)
        return newCursor
    }

    private fun requireRecord(): JSONObject =
        store.loadRecord() ?: throw IOException("Create a local sync identity first.")

    private fun validateLocalRecord(record: JSONObject) {
        val response = parseNative(
            bridge.nativeRestoreIdentity(
                record.getString(KEY_BUNDLE_BASE64), record.getString(KEY_LOCAL_PASSPHRASE)
            )
        )
        val restored = response.getJSONObject("card")
        val stored = JSONObject(record.getString(KEY_CARD_JSON))
        if (restored.optString("fingerprint_sha256") != stored.optString("fingerprint_sha256") ||
            restored.optString("device_id") != stored.optString("device_id")
        ) {
            throw IOException("Stored sync identity does not match its encrypted private bundle.")
        }
    }

    private fun newRecord(localPassphrase: String, bundleBase64: String, cardJson: String): JSONObject =
        JSONObject()
            .put("record_version", 1)
            .put(KEY_LOCAL_PASSPHRASE, localPassphrase)
            .put(KEY_BUNDLE_BASE64, bundleBase64)
            .put(KEY_CARD_JSON, cardJson)
            .put(KEY_RELAY_URL, "")
            .put(KEY_SPACE_ID, "")
            .put(KEY_CAPABILITY, "")
            .put(KEY_TRUSTED_CARDS, JSONObject())
            .put(KEY_REVOKED_FINGERPRINTS, JSONObject())
            .put(KEY_NEXT_SEQUENCE, 1L)
            .put(KEY_CURSOR, 0L)

    private fun parseNative(value: String): JSONObject {
        val response = try {
            JSONObject(value)
        } catch (exception: Exception) {
            throw SyncBridgeFailure("Native sync bridge returned an invalid response.")
        }
        if (!response.optBoolean("ok", false)) {
            throw SyncBridgeFailure(response.optString("error", "Native sync operation failed."))
        }
        return response
    }

    private fun randomLocalPassphrase(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return try {
            bytes.joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
        } finally {
            bytes.fill(0)
        }
    }

    private fun requireRecoveryPassphrase(value: String) {
        if (value.length < RECOVERY_PASSPHRASE_MIN_LENGTH) {
            throw IOException("Use a recovery passphrase with at least " + RECOVERY_PASSPHRASE_MIN_LENGTH + " characters.")
        }
    }

    companion object {
        private const val SYNC_DIRECTORY = "privacage-sync"
        private const val MAX_CARD_JSON_BYTES = 32 * 1024
        private const val MAX_PROFILE_BYTES = 1_048_576
        private const val MAX_RECOVERY_BUNDLE_BYTES = 1_100_000
        private const val MAX_TRUSTED_CARDS = 32
        private const val MAX_MESSAGES_PER_CHECK = 25
        private const val MESSAGE_TTL_SECONDS = 7L * 24 * 60 * 60
        const val RECOVERY_PASSPHRASE_MIN_LENGTH = 12
        private const val KEY_LOCAL_PASSPHRASE = "local_passphrase"
        private const val KEY_BUNDLE_BASE64 = "identity_bundle_base64"
        private const val KEY_CARD_JSON = "card_json"
        private const val KEY_RELAY_URL = "relay_url"
        private const val KEY_SPACE_ID = "space_id"
        private const val KEY_CAPABILITY = "capability_token"
        private const val KEY_TRUSTED_CARDS = "trusted_cards"
        private const val KEY_REVOKED_FINGERPRINTS = "revoked_fingerprints"
        private const val KEY_NEXT_SEQUENCE = "next_sequence"
        private const val KEY_CURSOR = "relay_cursor"
        private const val KEY_PENDING_PROFILE = "pending_profile_json"
        private const val KEY_PENDING_SENDER = "pending_sender_fingerprint"
    }
}
