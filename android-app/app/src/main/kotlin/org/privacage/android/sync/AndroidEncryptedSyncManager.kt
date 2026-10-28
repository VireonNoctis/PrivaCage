package org.privacage.android.sync

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import org.privacage.android.StrictJsonKeyScanner
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

internal data class OwnerRotationResult(
    val packageJson: String,
    val publicationMessage: String,
    val previousFingerprint: String,
    val nextFingerprint: String,
    val rosterRevision: Long
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
        validatePeerCardJson(cardJson)
        return parseNative(bridge.nativeVerifyIdentityCard(cardJson)).getJSONObject("card")
    }

    @Synchronized
    @Throws(IOException::class)
    fun trustPeerCard(cardJson: String, independentlyConfirmedFingerprint: String): String {
        validatePeerCardJson(cardJson)
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
        val addedAt = record.optJSONObject(KEY_TRUSTED_ADDED_AT) ?: JSONObject()
        if (!addedAt.has(fingerprint)) addedAt.put(fingerprint, System.currentTimeMillis() / 1000L)
        record.put(KEY_TRUSTED_ADDED_AT, addedAt)
        // Re-trust is possible only after the caller confirms the full fingerprint again.
        val revoked = record.optJSONObject(KEY_REVOKED_FINGERPRINTS) ?: JSONObject()
        revoked.remove(fingerprint)
        record.put(KEY_REVOKED_FINGERPRINTS, revoked)
        val revokedCards = record.optJSONObject(KEY_REVOKED_CARDS) ?: JSONObject()
        revokedCards.remove(fingerprint)
        record.put(KEY_REVOKED_CARDS, revokedCards)
        appendRosterHistory(record, "peer_trusted", fingerprint, "Peer fingerprint was independently confirmed.")
        store.saveRecord(record)
        if (record.optString(KEY_ROSTER_OWNER, "") == localFingerprint) {
            try {
                createSignedDeviceRoster()
            } catch (exception: IOException) {
                throw IOException("The peer is trusted locally, but publishing the updated roster failed. Retry roster publication; the local trust change was saved.", exception)
            }
        }
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
        validateLocalRecord(record)
        if (!trusted.has(fingerprint)) {
            throw IOException("This fingerprint is not currently trusted on this device.")
        }
        val revokedCard = trusted.optJSONObject(fingerprint)
        trusted.remove(fingerprint)
        record.put(KEY_TRUSTED_CARDS, trusted)
        val addedAt = record.optJSONObject(KEY_TRUSTED_ADDED_AT) ?: JSONObject()
        addedAt.remove(fingerprint)
        record.put(KEY_TRUSTED_ADDED_AT, addedAt)
        if (revokedCard != null) {
            val revokedCards = record.optJSONObject(KEY_REVOKED_CARDS) ?: JSONObject()
            revokedCards.put(fingerprint, revokedCard)
            record.put(KEY_REVOKED_CARDS, revokedCards)
        }

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
        appendRosterHistory(record, "peer_revoked_local", fingerprint, "Removed from this installation; publish a newer owner-signed roster to distribute the revocation.")
        store.saveRecord(record)
        return fingerprint
    }


    @Synchronized
    @Throws(IOException::class)
    fun revokeTrustedPeerAndPublishRoster(fingerprint: String): String {
        revokeTrustedPeer(fingerprint)
        val record = requireRecord()
        val localFingerprint = JSONObject(record.getString(KEY_CARD_JSON)).getString("fingerprint_sha256")
        val ownerFingerprint = record.optString(KEY_ROSTER_OWNER, "")
        if (ownerFingerprint != localFingerprint) {
            return "Trust was revoked locally. This installation is not the pinned roster owner, so it cannot publish the shared roster. Ask the owner to revoke this fingerprint there. If the device is lost, separately revoke its relay member credential with the relay administrator."
        }
        return try {
            val signed = createSignedDeviceRoster()
            val revision = JSONObject(signed).optJSONObject("unsigned")?.optLong("revision", 0L) ?: 0L
            "Trust was revoked and signed roster revision $revision was published. Other clients enforce it when they fetch the newer roster. The relay credential must still be revoked separately if the device is lost or compromised."
        } catch (exception: IOException) {
            throw IOException("Local trust revocation is saved, but roster publication failed. Retry 'Create / update owner-signed device roster' to publish the pending revision. The relay credential has not been revoked.", exception)
        }
    }


    @Synchronized
    @Throws(IOException::class)
    fun createSignedDeviceRoster(): String {
        val record = requireRecord()
        validateLocalRecord(record)
        val localCard = JSONObject(record.getString(KEY_CARD_JSON))
        val localFingerprint = localCard.getString("fingerprint_sha256")
        val pinnedOwner = record.optString(KEY_ROSTER_OWNER, "")
        if (pinnedOwner.isNotEmpty() && pinnedOwner != localFingerprint) {
            throw IOException("Only the pinned roster owner identity can sign roster updates.")
        }
        val spaceId = record.optString(KEY_SPACE_ID, "")
        if (!SyncRelayClient.isValidSpaceId(spaceId)) {
            throw IOException("Save the relay space ID before creating a signed device roster.")
        }
        if (record.optBoolean(KEY_ROSTER_PUBLISH_PENDING, false)) {
            val pendingRoster = record.optJSONObject(KEY_DEVICE_ROSTER)
                ?: throw IOException("A roster publish is pending, but the saved signed roster is missing.")
            relayClient(record).publishRoster(pendingRoster.toString())
            record.put(KEY_ROSTER_PUBLISH_PENDING, false)
            val pendingRevision = pendingRoster.optJSONObject("unsigned")?.optLong("revision", 0L) ?: 0L
            appendRosterHistory(record, "roster_published", null, "Published the previously signed roster revision after retry.", pendingRevision)
            store.saveRecord(record)
            // Do not return here: a newer local trust change may have been saved while this snapshot was pending.
            // The next revision below includes current trust state after the old snapshot is safely published.
        }
        val oldRevision = record.optLong(KEY_ROSTER_REVISION, 0L)
        if (oldRevision < 0L || oldRevision == Long.MAX_VALUE) {
            throw IOException("Roster revision is invalid or exhausted.")
        }
        val issuedAt = System.currentTimeMillis() / 1000L
        val members = mutableListOf<JSONObject>()
        members.add(rosterMember(localFingerprint, localCard, "active", 0L, null))

        val trusted = record.optJSONObject(KEY_TRUSTED_CARDS) ?: JSONObject()
        val addedAt = record.optJSONObject(KEY_TRUSTED_ADDED_AT) ?: JSONObject()
        val peerKeys = trusted.keys()
        while (peerKeys.hasNext()) {
            val fingerprint = peerKeys.next()
            if (fingerprint == localFingerprint) continue
            val card = trusted.optJSONObject(fingerprint)
                ?: throw IOException("A trusted device card is malformed; roster was not created.")
            members.add(rosterMember(fingerprint, card, "active", addedAt.optLong(fingerprint, 0L), null))
        }

        val revoked = record.optJSONObject(KEY_REVOKED_FINGERPRINTS) ?: JSONObject()
        val revokedCards = record.optJSONObject(KEY_REVOKED_CARDS) ?: JSONObject()
        val revokedKeys = revoked.keys()
        while (revokedKeys.hasNext()) {
            val fingerprint = revokedKeys.next()
            if (!validFingerprint(fingerprint) || trusted.has(fingerprint)) continue
            val revokedAt = revoked.optLong(fingerprint, 0L)
            if (revokedAt <= 0L || revokedAt > issuedAt) continue
            members.add(rosterMember(fingerprint, revokedCards.optJSONObject(fingerprint), "revoked", 0L, revokedAt))
        }
        if (members.size > MAX_ROSTER_MEMBERS) {
            throw IOException("Roster exceeds the supported 128 device entries including revocation tombstones.")
        }
        members.sortBy { it.getString("fingerprint_sha256") }
        val memberArray = org.json.JSONArray()
        members.forEach { memberArray.put(it) }

        val response = parseNative(
            bridge.nativeCreateDeviceRoster(
                record.getString(KEY_BUNDLE_BASE64),
                record.getString(KEY_LOCAL_PASSPHRASE),
                spaceId,
                oldRevision + 1L,
                issuedAt,
                memberArray.toString()
            )
        )
        val roster = response.getJSONObject("roster")
        record.put(KEY_ROSTER_OWNER, localFingerprint)
        record.put(KEY_ROSTER_REVISION, oldRevision + 1L)
        record.put(KEY_DEVICE_ROSTER, roster)
        record.put(KEY_ROSTER_PUBLISH_PENDING, true)
        appendRosterHistory(record, "roster_signed", null, "Signed roster revision " + (oldRevision + 1L) + " locally; publication is pending.", oldRevision + 1L)
        store.saveRecord(record)
        relayClient(record).publishRoster(roster.toString())
        record.put(KEY_ROSTER_PUBLISH_PENDING, false)
        appendRosterHistory(record, "roster_published", null, "Published owner-signed roster revision " + (oldRevision + 1L) + " to the relay.", oldRevision + 1L)
        store.saveRecord(record)
        return roster.toString()
    }

    @Synchronized
    @Throws(IOException::class)
    fun importSignedDeviceRoster(rosterJson: String, independentlyConfirmedOwnerFingerprint: String): String =
        importSignedDeviceRosterInternal(rosterJson, independentlyConfirmedOwnerFingerprint, null)

    @Throws(IOException::class)
    private fun importSignedDeviceRosterInternal(
        rosterJson: String,
        independentlyConfirmedOwnerFingerprint: String,
        ownerRotation: JSONObject?
    ): String {
        if (rosterJson.isBlank() || rosterJson.toByteArray(StandardCharsets.UTF_8).size > MAX_ROSTER_JSON_BYTES) {
            throw IOException("Paste a complete signed roster under 256 KiB.")
        }
        val expectedOwner = independentlyConfirmedOwnerFingerprint.trim().lowercase()
        if (!validFingerprint(expectedOwner)) {
            throw IOException("Owner fingerprint must be a full lowercase SHA-256 digest.")
        }
        val record = requireRecord()
        validateLocalRecord(record)
        val pinnedOwner = record.optString(KEY_ROSTER_OWNER, "")
        val currentRevision = record.optLong(KEY_ROSTER_REVISION, 0L)
        if (ownerRotation == null) {
            if (pinnedOwner.isNotEmpty() && pinnedOwner != expectedOwner) {
                throw IOException("Roster owner does not match the previously pinned owner.")
            }
        } else {
            val rotationUnsigned = ownerRotation.optJSONObject("unsigned")
                ?: throw IOException("Verified owner-key transition is malformed.")
            val previousCard = rotationUnsigned.optJSONObject("previous_owner_card")
                ?: throw IOException("Owner-key transition omits its previous owner card.")
            val nextCard = rotationUnsigned.optJSONObject("next_owner_card")
                ?: throw IOException("Owner-key transition omits its next owner card.")
            val priorOwnerCard = record.optJSONObject(KEY_DEVICE_ROSTER)
                ?.optJSONObject("unsigned")?.optJSONObject("owner_card")
                ?: throw IOException("Previously pinned roster owner card is missing.")
            if (pinnedOwner != previousCard.optString("fingerprint_sha256") ||
                !sameDeviceCard(previousCard, priorOwnerCard) ||
                expectedOwner != nextCard.optString("fingerprint_sha256") ||
                rotationUnsigned.optString("space_id") != record.optString(KEY_SPACE_ID, "") ||
                rotationUnsigned.optLong("previous_roster_revision", -1L) != currentRevision ||
                rotationUnsigned.optLong("next_roster_revision", -1L) != currentRevision + 1L
            ) {
                throw IOException("Owner-key transition no longer matches the currently pinned owner, space, or revision.")
            }
        }
        val minimumRevision = if (pinnedOwner == expectedOwner || ownerRotation != null) currentRevision else 0L
        val response = parseNative(
            bridge.nativeVerifyDeviceRoster(
                rosterJson, expectedOwner, minimumRevision, System.currentTimeMillis() / 1000L
            )
        )
        val roster = response.getJSONObject("roster")
        val unsigned = roster.getJSONObject("unsigned")
        val revision = unsigned.getLong("revision")
        if (revision <= minimumRevision) throw IOException("Roster revision did not advance; export a newer revision.")

        val rosterSpace = unsigned.getString("space_id")
        val configuredSpace = record.optString(KEY_SPACE_ID, "")
        if (configuredSpace.isNotEmpty() && configuredSpace != rosterSpace) {
            throw IOException("Signed roster belongs to a different relay space.")
        }
        if (ownerRotation != null) {
            val rotationUnsigned = ownerRotation.getJSONObject("unsigned")
            val nextOwnerCard = rotationUnsigned.getJSONObject("next_owner_card")
            if (revision != rotationUnsigned.getLong("next_roster_revision") ||
                revision != currentRevision + 1L ||
                rosterSpace != rotationUnsigned.getString("space_id") ||
                !sameDeviceCard(unsigned.getJSONObject("owner_card"), nextOwnerCard)
            ) {
                throw IOException("Signed roster is not the exact next revision authorized by the owner-key transition.")
            }
        }

        val previousRevision = record.optLong(KEY_ROSTER_REVISION, 0L)
        val localCard = JSONObject(record.getString(KEY_CARD_JSON))
        val localFingerprint = localCard.getString("fingerprint_sha256")
        val trusted = JSONObject()
        val addedAt = JSONObject()
        val revoked = JSONObject()
        val revokedCards = JSONObject()
        val priorTrusted = record.optJSONObject(KEY_TRUSTED_CARDS) ?: JSONObject()
        val priorRevokedCards = record.optJSONObject(KEY_REVOKED_CARDS) ?: JSONObject()
        val pendingRotation = record.optJSONObject(KEY_PENDING_KEY_ROTATION)
        val pendingNextCard = pendingRotation?.optJSONObject("next_card")
        val pendingNextFingerprint = pendingNextCard?.optString("fingerprint_sha256", "").orEmpty()
        val members = unsigned.getJSONArray("members")
        var localMemberFound = false
        var pendingRotationAuthorized = false
        var revokedCount = 0
        for (index in 0 until members.length()) {
            val member = members.getJSONObject(index)
            val fingerprint = member.getString("fingerprint_sha256")
            val status = member.getString("status")
            val card = member.optJSONObject("card")
            if (fingerprint == localFingerprint) {
                if (status == "active" && card != null && sameDeviceCard(card, localCard)) {
                    localMemberFound = true
                } else if (pendingRotation == null) {
                    throw IOException("Roster does not include this exact local identity as active.")
                } else if (status == "revoked") {
                    revoked.put(fingerprint, member.getLong("revoked_at_unix"))
                    revokedCards.put(fingerprint, localCard)
                }
                continue
            }
            if (pendingRotation != null && fingerprint == pendingNextFingerprint) {
                if (status != "active" || card == null || pendingNextCard == null || !sameDeviceCard(card, pendingNextCard)) {
                    throw IOException("Roster does not authorize the exact staged replacement identity.")
                }
                pendingRotationAuthorized = true
                continue
            }
            when (status) {
                "active" -> {
                    val activeCard = card ?: throw IOException("Active roster member has no public device card.")
                    trusted.put(fingerprint, activeCard)
                    addedAt.put(fingerprint, member.optLong("added_at_unix", 0L))
                }
                "revoked" -> {
                    revoked.put(fingerprint, member.getLong("revoked_at_unix"))
                    val knownCard = card ?: priorRevokedCards.optJSONObject(fingerprint)
                        ?: priorTrusted.optJSONObject(fingerprint)
                    if (knownCard != null) revokedCards.put(fingerprint, knownCard)
                    revokedCount += 1
                }
                else -> throw IOException("Roster contains an unknown member status.")
            }
        }
        if (!localMemberFound && !pendingRotationAuthorized) {
            throw IOException("Roster does not authorize this device or its verified staged replacement; nothing was imported.")
        }
        if (trusted.length() > MAX_TRUSTED_CARDS) {
            throw IOException("Roster exceeds the 32 active peer cards supported by this Android client.")
        }

        val previousPeerKeys = priorTrusted.keys()
        while (previousPeerKeys.hasNext()) {
            val fingerprint = previousPeerKeys.next()
            if (!trusted.has(fingerprint)) {
                val eventType = if (revoked.has(fingerprint)) "peer_revoked_by_roster" else "peer_removed_by_roster"
                appendRosterHistory(record, eventType, fingerprint, "Roster revision $revision changed this peer's active membership.", revision)
            }
        }
        val currentPeerKeys = trusted.keys()
        while (currentPeerKeys.hasNext()) {
            val fingerprint = currentPeerKeys.next()
            if (!priorTrusted.has(fingerprint)) {
                appendRosterHistory(record, "peer_added_by_roster", fingerprint, "Roster revision $revision authorized this peer.", revision)
            }
        }
        if (revision > previousRevision + 1L) {
            appendRosterHistory(
                record, "roster_history_gap", null,
                "Imported revision $revision after local revision $previousRevision; one or more older snapshots were not available from the relay.",
                revision
            )
        }
        record.put(KEY_TRUSTED_CARDS, trusted)
        record.put(KEY_TRUSTED_ADDED_AT, addedAt)
        record.put(KEY_REVOKED_FINGERPRINTS, revoked)
        record.put(KEY_REVOKED_CARDS, revokedCards)
        record.put(KEY_ROSTER_OWNER, expectedOwner)
        record.put(KEY_ROSTER_REVISION, revision)
        record.put(KEY_DEVICE_ROSTER, roster)
        val pendingSender = record.optString(KEY_PENDING_SENDER, "")
        if (pendingSender.isNotEmpty() && !trusted.has(pendingSender)) {
            record.remove(KEY_PENDING_PROFILE)
            record.remove(KEY_PENDING_SENDER)
        }

        if (pendingRotationAuthorized && pendingRotation != null && pendingNextCard != null) {
            val nextBundle = pendingRotation.optString("next_bundle_base64", "")
            val nextPassphrase = pendingRotation.optString("next_local_passphrase", "")
            if (nextBundle.isBlank() || nextPassphrase.isBlank()) {
                throw IOException("Staged key rotation is incomplete; current identity was not replaced.")
            }
            val restoredNext = parseNative(bridge.nativeRestoreIdentity(nextBundle, nextPassphrase)).getJSONObject("card")
            if (!sameDeviceCard(restoredNext, pendingNextCard)) {
                throw IOException("Staged replacement private key does not match its signed public card.")
            }
            val previousFingerprint = pendingRotation.optString("previous_fingerprint", localFingerprint)
            record.put(KEY_BUNDLE_BASE64, nextBundle)
            record.put(KEY_LOCAL_PASSPHRASE, nextPassphrase)
            record.put(KEY_CARD_JSON, pendingNextCard.toString())
            record.put(KEY_NEXT_SEQUENCE, 1L)
            record.remove(KEY_PENDING_KEY_ROTATION)
            appendRosterHistory(
                record, "key_rotation_activated", pendingNextFingerprint,
                "Activated the staged identity after owner-signed roster revision $revision authorized it; previous fingerprint was $previousFingerprint.",
                revision
            )
        }
        appendRosterHistory(
            record, "roster_imported", null,
            "Verified and applied owner-signed roster revision $revision; active peers: " + trusted.length() + "; revoked entries: " + revokedCount + ".",
            revision
        )
        store.saveRecord(record)
        return "Verified owner-signed roster revision " + revision + ". Active peers: " + trusted.length() +
            "; revoked entries: " + revokedCount +
            if (pendingRotationAuthorized) ". The staged replacement identity is now active; update the relay credential if member mode is enabled."
            else ". Relay administrator membership is separate."
    }

    @Synchronized
    @Throws(IOException::class)
    fun syncSignedRosterFromRelay(): String {
        val record = requireRecord()
        validateLocalRecord(record)
        val currentOwnerPin = record.optString(KEY_ROSTER_OWNER, "")
        val localFingerprint = JSONObject(record.getString(KEY_CARD_JSON)).getString("fingerprint_sha256")
        val currentRevision = record.optLong(KEY_ROSTER_REVISION, 0L)
        if (record.optString(KEY_RELAY_URL, "").isBlank() ||
            record.optString(KEY_SPACE_ID, "").isBlank() ||
            record.optString(KEY_CAPABILITY, "").isBlank()
        ) {
            return "Signed roster sync skipped: relay configuration is not saved."
        }
        if (record.optBoolean(KEY_ROSTER_PUBLISH_PENDING, false)) {
            val pendingRoster = record.optJSONObject(KEY_DEVICE_ROSTER)
                ?: throw IOException("Roster publication is pending, but its signed snapshot is missing.")
            relayClient(record).publishRoster(pendingRoster.toString())
            record.put(KEY_ROSTER_PUBLISH_PENDING, false)
            val pendingRevision = pendingRoster.optJSONObject("unsigned")?.optLong("revision", 0L) ?: 0L
            appendRosterHistory(record, "roster_published", null, "Published the pending signed roster during roster synchronization.", pendingRevision)
            store.saveRecord(record)
        }

        val page = relayClient(record).fetchRostersAfter(currentRevision, MAX_ROSTERS_PER_PULL)
        if (page.rosters.isEmpty()) {
            return if (currentOwnerPin.isBlank()) {
                "No signed roster is published yet. First import from another owner requires an independently confirmed owner fingerprint."
            } else {
                "Signed roster is current at revision $currentRevision."
            }
        }
        var ownerPin = currentOwnerPin
        var imported = 0
        var latestRevision = currentRevision
        for (entry in page.rosters) {
            if (ownerPin.isBlank()) {
                if (entry.ownerFingerprint != localFingerprint) {
                    throw IOException("A first roster cannot be trusted from the relay alone. Import it manually after confirming the owner's full fingerprint through a separate trusted channel.")
                }
                ownerPin = localFingerprint
            }
            if (entry.ownerFingerprint != ownerPin) {
                throw IOException("Relay roster owner changed. The pinned owner identity was not changed.")
            }
            importSignedDeviceRoster(entry.rosterJson, ownerPin)
            latestRevision = entry.revision
            imported += 1
        }
        val suffix = if (page.rosters.size == MAX_ROSTERS_PER_PULL) " More history may remain; synchronize again to continue." else ""
        return "Verified and imported $imported signed roster revision(s), through revision $latestRevision.$suffix"
    }

    @Synchronized
    @Throws(IOException::class)
    fun rotateRosterOwnerKey(): OwnerRotationResult {
        val record = requireRecord()
        validateLocalRecord(record)
        if (record.has(KEY_PENDING_KEY_ROTATION)) {
            throw IOException("Finish the staged peer-key rotation before rotating the roster owner.")
        }
        if (record.optBoolean(KEY_OWNER_ROTATION_HANDOFF_PENDING, false)) {
            throw IOException("The previous owner-key rotation package is still awaiting handoff confirmation. Copy the saved package to the trusted devices, then explicitly confirm that they accepted the transition before rotating again.")
        }
        if (record.optBoolean(KEY_ROSTER_PUBLISH_PENDING, false)) {
            throw IOException("Publish or retry the current roster before rotating the owner key.")
        }
        val oldCard = JSONObject(record.getString(KEY_CARD_JSON))
        val oldFingerprint = oldCard.getString("fingerprint_sha256")
        if (record.optString(KEY_ROSTER_OWNER, "") != oldFingerprint) {
            throw IOException("Only the currently pinned roster owner can rotate the owner key.")
        }
        val oldRoster = record.optJSONObject(KEY_DEVICE_ROSTER)
            ?: throw IOException("Create and publish an owner-signed roster before rotating the owner key.")
        val oldUnsigned = oldRoster.optJSONObject("unsigned")
            ?: throw IOException("The current signed roster is malformed.")
        val spaceId = record.optString(KEY_SPACE_ID, "")
        if (!SyncRelayClient.isValidSpaceId(spaceId) || oldUnsigned.optString("space_id") != spaceId) {
            throw IOException("The saved relay space does not match the current signed roster.")
        }
        val oldRevision = record.optLong(KEY_ROSTER_REVISION, 0L)
        if (oldRevision < 1L || oldRevision == Long.MAX_VALUE) {
            throw IOException("The current owner roster revision is invalid or exhausted.")
        }

        val nextPassphrase = randomLocalPassphrase()
        val issuedAt = System.currentTimeMillis() / 1000L
        val response = parseNative(
            bridge.nativeRotateOwnerKey(
                record.getString(KEY_BUNDLE_BASE64),
                record.getString(KEY_LOCAL_PASSPHRASE),
                nextPassphrase,
                spaceId,
                oldRevision,
                issuedAt
            )
        )
        val previousCard = response.getJSONObject("previous_owner_card")
        val nextCard = response.getJSONObject("next_owner_card")
        if (!sameDeviceCard(previousCard, oldCard) ||
            nextCard.optLong("key_epoch", 0L) != oldCard.optLong("key_epoch", 0L) + 1L ||
            nextCard.optString("fingerprint_sha256") == oldFingerprint
        ) {
            throw IOException("Native owner rotation did not produce the expected predecessor and next identity.")
        }
        val transition = response.getJSONObject("transition")
        val nextBundle = response.getString("next_bundle_base64")
        val nextFingerprint = nextCard.getString("fingerprint_sha256")
        val nextRevision = oldRevision + 1L

        val memberByFingerprint = linkedMapOf<String, JSONObject>()
        memberByFingerprint[nextFingerprint] = rosterMember(nextFingerprint, nextCard, "active", issuedAt, null)
        val trusted = record.optJSONObject(KEY_TRUSTED_CARDS) ?: JSONObject()
        val addedAt = record.optJSONObject(KEY_TRUSTED_ADDED_AT) ?: JSONObject()
        val trustedKeys = trusted.keys()
        while (trustedKeys.hasNext()) {
            val fingerprint = trustedKeys.next()
            if (fingerprint == oldFingerprint || fingerprint == nextFingerprint) {
                throw IOException("Trusted peer list conflicts with the current or replacement owner identity.")
            }
            val unverifiedCard = trusted.optJSONObject(fingerprint)
                ?: throw IOException("A trusted peer card is malformed; owner rotation cancelled.")
            val verifiedCard = parseNative(bridge.nativeVerifyIdentityCard(unverifiedCard.toString()))
                .getJSONObject("card")
            if (verifiedCard.optString("fingerprint_sha256") != fingerprint) {
                throw IOException("A trusted peer card is indexed under a different fingerprint.")
            }
            memberByFingerprint[fingerprint] = rosterMember(
                fingerprint, verifiedCard, "active", addedAt.optLong(fingerprint, 0L), null
            )
        }
        // The previous owner remains as a public revocation tombstone so clients can
        // distinguish an authorized transition from a fresh, unrelated owner key.
        memberByFingerprint[oldFingerprint] = rosterMember(
            oldFingerprint, oldCard, "revoked", 0L, issuedAt
        )
        val revoked = record.optJSONObject(KEY_REVOKED_FINGERPRINTS) ?: JSONObject()
        val revokedCards = record.optJSONObject(KEY_REVOKED_CARDS) ?: JSONObject()
        val revokedKeys = revoked.keys()
        while (revokedKeys.hasNext()) {
            val fingerprint = revokedKeys.next()
            if (fingerprint == oldFingerprint || memberByFingerprint.containsKey(fingerprint) || !validFingerprint(fingerprint)) continue
            val revokedAt = revoked.optLong(fingerprint, 0L)
            if (revokedAt <= 0L || revokedAt > issuedAt) continue
            memberByFingerprint[fingerprint] = rosterMember(
                fingerprint, revokedCards.optJSONObject(fingerprint), "revoked", 0L, revokedAt
            )
        }
        if (memberByFingerprint.size > MAX_ROSTER_MEMBERS) {
            throw IOException("The rotated roster exceeds the 128-entry limit including revocation tombstones.")
        }
        val members = org.json.JSONArray()
        memberByFingerprint.toSortedMap().values.forEach { members.put(it) }

        val roster = parseNative(
            bridge.nativeCreateDeviceRoster(
                nextBundle,
                nextPassphrase,
                spaceId,
                nextRevision,
                issuedAt,
                members.toString()
            )
        ).getJSONObject("roster")
        val newOwner = roster.optJSONObject("unsigned")?.optJSONObject("owner_card")
            ?: throw IOException("Native owner rotation returned a roster without an owner card.")
        val verifiedRoster = parseNative(
            bridge.nativeVerifyDeviceRoster(roster.toString(), nextFingerprint, oldRevision, issuedAt)
        ).getJSONObject("roster")
        val rosterUnsigned = verifiedRoster.getJSONObject("unsigned")
        if (!sameDeviceCard(newOwner, nextCard) ||
            rosterUnsigned.getLong("revision") != nextRevision ||
            rosterUnsigned.getString("space_id") != spaceId
        ) {
            throw IOException("Replacement owner roster does not match the signed transition.")
        }

        val packageJson = JSONObject()
            .put("format", OWNER_ROTATION_PACKAGE_FORMAT)
            .put("schema_version", 1)
            .put("transition", transition)
            .put("signed_roster", verifiedRoster)
            .toString(2)
        if (packageJson.toByteArray(StandardCharsets.UTF_8).size > MAX_OWNER_ROTATION_PACKAGE_BYTES) {
            throw IOException("Signed owner-key rotation package exceeds the 512 KiB limit.")
        }

        val revokedNow = record.optJSONObject(KEY_REVOKED_FINGERPRINTS) ?: JSONObject()
        revokedNow.put(oldFingerprint, issuedAt)
        record.put(KEY_REVOKED_FINGERPRINTS, revokedNow)
        val revokedCardMap = record.optJSONObject(KEY_REVOKED_CARDS) ?: JSONObject()
        revokedCardMap.put(oldFingerprint, oldCard)
        record.put(KEY_REVOKED_CARDS, revokedCardMap)
        record.put(KEY_BUNDLE_BASE64, nextBundle)
        record.put(KEY_LOCAL_PASSPHRASE, nextPassphrase)
        record.put(KEY_CARD_JSON, nextCard.toString())
        record.put(KEY_ROSTER_OWNER, nextFingerprint)
        record.put(KEY_ROSTER_REVISION, nextRevision)
        record.put(KEY_DEVICE_ROSTER, verifiedRoster)
        record.put(KEY_ROSTER_PUBLISH_PENDING, true)
        record.put(KEY_OWNER_ROTATION_PACKAGE_JSON, packageJson)
        record.put(KEY_OWNER_ROTATION_HANDOFF_PENDING, true)
        record.put(KEY_NEXT_SEQUENCE, 1L)
        appendRosterHistory(
            record, "owner_key_rotation_signed", nextFingerprint,
            "Created a dual-signed owner-key transition from $oldFingerprint to $nextFingerprint and signed replacement roster revision $nextRevision.",
            nextRevision
        )
        store.saveRecord(record)

        var publicationMessage = "The new owner identity and signed roster are saved locally; relay publication is pending. Retry roster publication before relying on automatic roster sync."
        try {
            relayClient(record).publishRoster(verifiedRoster.toString())
            record.put(KEY_ROSTER_PUBLISH_PENDING, false)
            appendRosterHistory(
                record, "owner_key_rotation_roster_published", nextFingerprint,
                "Published replacement owner-signed roster revision $nextRevision to the relay.",
                nextRevision
            )
            store.saveRecord(record)
            publicationMessage = "Replacement owner-signed roster revision $nextRevision was published to the relay."
        } catch (exception: Exception) {
            appendRosterHistory(
                record, "owner_key_rotation_publish_failed", nextFingerprint,
                "The owner identity and signed roster are saved locally, but relay publication failed. The signed roster remains pending for retry.",
                nextRevision
            )
            store.saveRecord(record)
        }

        return OwnerRotationResult(
            packageJson = packageJson,
            publicationMessage = publicationMessage,
            previousFingerprint = oldFingerprint,
            nextFingerprint = nextFingerprint,
            rosterRevision = nextRevision
        )
    }

    @Synchronized
    @Throws(IOException::class)
    fun lastOwnerKeyRotationPackage(): String {
        val record = requireRecord()
        validateLocalRecord(record)
        val packageJson = record.optString(KEY_OWNER_ROTATION_PACKAGE_JSON, "")
        if (packageJson.isBlank() || packageJson.toByteArray(StandardCharsets.UTF_8).size > MAX_OWNER_ROTATION_PACKAGE_BYTES) {
            throw IOException("No valid saved owner-key rotation package is available on this installation.")
        }
        val wrapper = try {
            JSONObject(packageJson)
        } catch (exception: Exception) {
            throw IOException("Saved owner-key rotation package is malformed.", exception)
        }
        val allowedKeys = setOf("format", "schema_version", "transition", "signed_roster")
        val keys = wrapper.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            if (key !in allowedKeys) throw IOException("Saved owner-key rotation package contains unsupported field '$key'.")
        }
        if (wrapper.length() != allowedKeys.size ||
            wrapper.optString("format") != OWNER_ROTATION_PACKAGE_FORMAT ||
            wrapper.optInt("schema_version", -1) != 1
        ) {
            throw IOException("Saved owner-key rotation package has an unsupported format.")
        }
        val transition = wrapper.optJSONObject("transition")
            ?: throw IOException("Saved owner-key rotation package omitted its transition.")
        val signedRoster = wrapper.optJSONObject("signed_roster")
            ?: throw IOException("Saved owner-key rotation package omitted its signed roster.")
        val transitionUnsigned = transition.optJSONObject("unsigned")
            ?: throw IOException("Saved owner-key transition is malformed.")
        val previousCard = transitionUnsigned.optJSONObject("previous_owner_card")
            ?: throw IOException("Saved owner-key transition omitted the predecessor card.")
        val nextCard = transitionUnsigned.optJSONObject("next_owner_card")
            ?: throw IOException("Saved owner-key transition omitted the replacement card.")
        val currentCard = JSONObject(record.getString(KEY_CARD_JSON))
        val currentFingerprint = currentCard.getString("fingerprint_sha256")
        val previousFingerprint = previousCard.optString("fingerprint_sha256", "")
        // The package is retained inside the authenticated Keystore-encrypted record.
        // Re-export must not depend on the predecessor remaining in the editable trust list.
        val spaceId = record.optString(KEY_SPACE_ID, "")
        val previousRevision = transitionUnsigned.optLong("previous_roster_revision", -1L)
        val nextRevision = transitionUnsigned.optLong("next_roster_revision", -1L)
        if (!validFingerprint(previousFingerprint) ||
            !sameDeviceCard(currentCard, nextCard) ||
            transitionUnsigned.optString("space_id") != spaceId ||
            nextRevision != previousRevision + 1L ||
            previousRevision < 1L
        ) {
            throw IOException("Saved owner-key rotation package no longer matches the local owner, space, or predecessor record.")
        }
        parseNative(
            bridge.nativeVerifyOwnerKeyRotation(
                previousCard.toString(),
                transition.toString(),
                spaceId,
                previousRevision,
                currentFingerprint,
                System.currentTimeMillis() / 1000L
            )
        )
        val verifiedRoster = parseNative(
            bridge.nativeVerifyDeviceRoster(
                signedRoster.toString(), currentFingerprint, previousRevision, System.currentTimeMillis() / 1000L
            )
        ).getJSONObject("roster")
        val unsigned = verifiedRoster.getJSONObject("unsigned")
        if (unsigned.getLong("revision") != nextRevision ||
            unsigned.getString("space_id") != spaceId ||
            !sameDeviceCard(unsigned.getJSONObject("owner_card"), currentCard)
        ) {
            throw IOException("Saved owner-key rotation roster is not the exact signed next revision.")
        }
        return packageJson
    }

    @Synchronized
    @Throws(IOException::class)
    fun confirmOwnerKeyRotationHandoff(independentlyConfirmedCurrentOwnerFingerprint: String): String {
        val record = requireRecord()
        validateLocalRecord(record)
        val current = JSONObject(record.getString(KEY_CARD_JSON)).getString("fingerprint_sha256")
        if (independentlyConfirmedCurrentOwnerFingerprint.trim().lowercase() != current) {
            throw IOException("Confirmed owner fingerprint does not match this installation's current owner identity.")
        }
        lastOwnerKeyRotationPackage()
        if (!record.optBoolean(KEY_OWNER_ROTATION_HANDOFF_PENDING, false)) {
            throw IOException("There is no pending owner-key handoff to confirm.")
        }
        record.put(KEY_OWNER_ROTATION_HANDOFF_PENDING, false)
        appendRosterHistory(
            record, "owner_key_rotation_handoff_confirmed", current,
            "User confirmed that the saved dual-signed owner transition was distributed and accepted by every intended trusted device. The public package remains stored for re-copying.",
            record.optLong(KEY_ROSTER_REVISION, 0L)
        )
        store.saveRecord(record)
        return "Owner-key handoff marked complete. The last public rotation package remains saved for re-copying; a later owner rotation may replace it."
    }

    @Synchronized
    @Throws(IOException::class)
    fun importOwnerKeyRotationPackage(
        packageJson: String,
        independentlyConfirmedNextOwnerFingerprint: String
    ): String {
        if (packageJson.isBlank() || packageJson.toByteArray(StandardCharsets.UTF_8).size > MAX_OWNER_ROTATION_PACKAGE_BYTES) {
            throw IOException("Owner-key rotation package is empty or exceeds the 512 KiB limit.")
        }
        val rotationPackage = try {
            JSONObject(packageJson)
        } catch (exception: Exception) {
            throw IOException("Owner-key rotation package is not valid JSON.", exception)
        }
        val allowedKeys = setOf("format", "schema_version", "transition", "signed_roster")
        val keys = rotationPackage.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            if (key !in allowedKeys) throw IOException("Owner-key rotation package contains unsupported field '$key'.")
        }
        if (rotationPackage.length() != allowedKeys.size ||
            rotationPackage.optString("format") != OWNER_ROTATION_PACKAGE_FORMAT ||
            rotationPackage.optInt("schema_version", -1) != 1
        ) {
            throw IOException("Unsupported owner-key rotation package format.")
        }
        val transition = rotationPackage.optJSONObject("transition")
            ?: throw IOException("Owner-key rotation package omits its transition.")
        val signedRoster = rotationPackage.optJSONObject("signed_roster")
            ?: throw IOException("Owner-key rotation package omits its new signed roster.")
        val expectedNextFingerprint = independentlyConfirmedNextOwnerFingerprint.trim().lowercase()
        if (!validFingerprint(expectedNextFingerprint)) {
            throw IOException("Replacement owner fingerprint must be the complete lowercase SHA-256 digest.")
        }

        val record = requireRecord()
        validateLocalRecord(record)
        if (record.has(KEY_PENDING_KEY_ROTATION)) {
            throw IOException("Finish the local peer-key rotation before importing an owner-key rotation.")
        }
        val pinnedOwner = record.optString(KEY_ROSTER_OWNER, "")
        val currentRevision = record.optLong(KEY_ROSTER_REVISION, 0L)
        val currentRoster = record.optJSONObject(KEY_DEVICE_ROSTER)
            ?: throw IOException("A previously pinned, verified owner roster is required before owner rotation.")
        if (!validFingerprint(pinnedOwner) || currentRevision < 1L) {
            throw IOException("Current owner pin and roster revision are invalid.")
        }
        val currentOwnerCard = currentRoster.optJSONObject("unsigned")?.optJSONObject("owner_card")
            ?: throw IOException("The pinned roster does not contain its owner public card.")
        if (currentOwnerCard.optString("fingerprint_sha256") != pinnedOwner) {
            throw IOException("Stored owner card does not match the existing owner pin.")
        }
        val spaceId = record.optString(KEY_SPACE_ID, "")
        val configuredSpace = currentRoster.optJSONObject("unsigned")?.optString("space_id", "").orEmpty()
        if (spaceId.isBlank() || configuredSpace != spaceId) {
            throw IOException("Configured relay space does not match the currently pinned roster.")
        }
        if (currentRevision == Long.MAX_VALUE) {
            throw IOException("Current roster revision is exhausted and cannot accept a further owner transition.")
        }
        val verifiedTransition = parseNative(
            bridge.nativeVerifyOwnerKeyRotation(
                currentOwnerCard.toString(),
                transition.toString(),
                spaceId,
                currentRevision,
                expectedNextFingerprint,
                System.currentTimeMillis() / 1000L
            )
        )
        val nextOwnerCard = verifiedTransition.getJSONObject("next_owner_card")
        val transitionUnsigned = transition.getJSONObject("unsigned")
        val nextRevision = verifiedTransition.getLong("next_roster_revision")
        if (verifiedTransition.getString("previous_owner_fingerprint") != pinnedOwner ||
            transitionUnsigned.optString("space_id") != spaceId ||
            nextRevision != currentRevision + 1L ||
            transitionUnsigned.optLong("previous_roster_revision", -1L) != currentRevision
        ) {
            throw IOException("Owner-key transition does not continue the exact currently pinned space and revision.")
        }
        val verifiedRoster = parseNative(
            bridge.nativeVerifyDeviceRoster(
                signedRoster.toString(), expectedNextFingerprint, currentRevision, System.currentTimeMillis() / 1000L
            )
        ).getJSONObject("roster")
        val unsigned = verifiedRoster.getJSONObject("unsigned")
        if (!sameDeviceCard(unsigned.getJSONObject("owner_card"), nextOwnerCard) ||
            unsigned.getLong("revision") != nextRevision ||
            unsigned.getString("space_id") != spaceId
        ) {
            throw IOException("New signed roster is not the exact next revision authorized by the owner-key transition.")
        }

        val result = importSignedDeviceRosterInternal(verifiedRoster.toString(), expectedNextFingerprint, transition)
        val updated = requireRecord()
        appendRosterHistory(
            updated, "owner_key_rotation_imported", expectedNextFingerprint,
            "Accepted a dual-signed owner-key transition from $pinnedOwner to $expectedNextFingerprint after independently confirming the complete new fingerprint; applied signed roster revision $nextRevision.",
            nextRevision
        )
        store.saveRecord(updated)
        return result + " Owner key changed from $pinnedOwner to $expectedNextFingerprint after dual-signature and independent-fingerprint checks."
    }

    @Synchronized
    @Throws(IOException::class)
    fun stageLocalKeyRotation(): String {
        val record = requireRecord()
        validateLocalRecord(record)
        val localCard = JSONObject(record.getString(KEY_CARD_JSON))
        val localFingerprint = localCard.getString("fingerprint_sha256")
        val ownerFingerprint = record.optString(KEY_ROSTER_OWNER, "")
        if (ownerFingerprint.isBlank() || !record.has(KEY_DEVICE_ROSTER)) {
            throw IOException("Import or publish the initial signed roster before rotating a peer identity.")
        }
        if (ownerFingerprint == localFingerprint) {
            throw IOException("This peer-key rotation flow is for non-owner devices. Use 'Rotate roster owner key' for the pinned roster owner.")
        }
        if (record.has(KEY_PENDING_KEY_ROTATION)) {
            throw IOException("A key rotation is already staged. Finish it or restore from the current recovery bundle first.")
        }
        if (!isRosterMemberActive(record, localFingerprint)) {
            throw IOException("The current identity is not active in the pinned owner-signed roster.")
        }
        val nextPassphrase = randomLocalPassphrase()
        val response = parseNative(
            bridge.nativeRotateIdentity(
                record.getString(KEY_BUNDLE_BASE64),
                record.getString(KEY_LOCAL_PASSPHRASE),
                nextPassphrase
            )
        )
        val previousCard = response.getJSONObject("previous_card")
        val nextCard = response.getJSONObject("next_card")
        if (!sameDeviceCard(previousCard, localCard)) {
            throw IOException("Native rotation did not preserve the current identity as its predecessor.")
        }
        val rotation = response.getJSONObject("rotation")
        val pending = JSONObject()
            .put("previous_fingerprint", localFingerprint)
            .put("next_card", nextCard)
            .put("rotation_json", rotation)
            .put("next_bundle_base64", response.getString("next_bundle_base64"))
            .put("next_local_passphrase", nextPassphrase)
            .put("staged_at_unix", System.currentTimeMillis() / 1000L)
        record.put(KEY_PENDING_KEY_ROTATION, pending)
        appendRosterHistory(
            record, "key_rotation_staged", localFingerprint,
            "Generated a replacement identity and a previous-key-signed transition. Existing identity remains active until a newer owner-signed roster authorizes the replacement."
        )
        store.saveRecord(record)
        return JSONObject()
            .put("previous_card", previousCard)
            .put("next_card", nextCard)
            .put("rotation", rotation)
            .toString()
    }

    @Synchronized
    @Throws(IOException::class)
    fun acceptPeerKeyRotation(rotationPackageJson: String): String {
        if (rotationPackageJson.isBlank() || rotationPackageJson.toByteArray(StandardCharsets.UTF_8).size > MAX_ROTATION_PACKAGE_BYTES) {
            throw IOException("Rotation package is empty or exceeds the supported size.")
        }
        val packageJson = try {
            JSONObject(rotationPackageJson)
        } catch (exception: Exception) {
            throw IOException("Rotation package is not valid JSON.", exception)
        }
        val previousCard = packageJson.optJSONObject("previous_card")
            ?: throw IOException("Rotation package omitted the previous public device card.")
        val nextCard = packageJson.optJSONObject("next_card")
            ?: throw IOException("Rotation package omitted the replacement public device card.")
        val rotation = packageJson.optJSONObject("rotation")
            ?: throw IOException("Rotation package omitted the previous-key-signed transition.")
        val record = requireRecord()
        validateLocalRecord(record)
        val verified = parseNative(
            bridge.nativeVerifyKeyRotation(
                previousCard.toString(), rotation.toString(), System.currentTimeMillis() / 1000L
            )
        )
        val verifiedNext = verified.getJSONObject("next_card")
        if (!sameDeviceCard(nextCard, verifiedNext)) {
            throw IOException("Rotation package replacement card does not match the signed transition.")
        }
        val previousFingerprint = verified.getString("previous_fingerprint")
        val nextFingerprint = verifiedNext.getString("fingerprint_sha256")
        val localFingerprint = JSONObject(record.getString(KEY_CARD_JSON)).getString("fingerprint_sha256")
        val ownerFingerprint = record.optString(KEY_ROSTER_OWNER, "")
        if (ownerFingerprint.isBlank() || !record.has(KEY_DEVICE_ROSTER)) {
            throw IOException("A pinned signed roster is required before accepting a peer key rotation.")
        }
        if (previousFingerprint == localFingerprint || previousFingerprint == ownerFingerprint) {
            throw IOException("The roster owner cannot rotate through the peer-rotation workflow.")
        }
        if (nextFingerprint == localFingerprint || nextFingerprint == previousFingerprint) {
            throw IOException("Rotation package does not represent a different peer identity.")
        }
        val trusted = record.optJSONObject(KEY_TRUSTED_CARDS) ?: JSONObject()
        val knownPrevious = trusted.optJSONObject(previousFingerprint)
            ?: throw IOException("Previous identity is not currently trusted; rotation continuity cannot be established.")
        if (!sameDeviceCard(knownPrevious, previousCard)) {
            throw IOException("Rotation predecessor does not match the exact previously trusted public card.")
        }
        if (!isRosterMemberActive(record, previousFingerprint)) {
            throw IOException("Previous identity is not active in the pinned owner-signed roster.")
        }
        val alreadyKnownNext = trusted.optJSONObject(nextFingerprint)
        if (alreadyKnownNext != null && !sameDeviceCard(alreadyKnownNext, verifiedNext)) {
            throw IOException("Replacement fingerprint already maps to a different recorded card.")
        }
        if (alreadyKnownNext == null && trusted.length() >= MAX_TRUSTED_CARDS) {
            throw IOException("Trusted-device list is full. Remove another peer before accepting this rotation.")
        }
        trusted.put(nextFingerprint, verifiedNext)
        record.put(KEY_TRUSTED_CARDS, trusted)
        val addedAt = record.optJSONObject(KEY_TRUSTED_ADDED_AT) ?: JSONObject()
        if (!addedAt.has(nextFingerprint)) addedAt.put(nextFingerprint, System.currentTimeMillis() / 1000L)
        record.put(KEY_TRUSTED_ADDED_AT, addedAt)
        val revoked = record.optJSONObject(KEY_REVOKED_FINGERPRINTS) ?: JSONObject()
        revoked.remove(nextFingerprint)
        record.put(KEY_REVOKED_FINGERPRINTS, revoked)
        val revokedCards = record.optJSONObject(KEY_REVOKED_CARDS) ?: JSONObject()
        revokedCards.remove(nextFingerprint)
        record.put(KEY_REVOKED_CARDS, revokedCards)
        appendRosterHistory(
            record, "peer_key_rotation_accepted", nextFingerprint,
            "Accepted signed key transition from $previousFingerprint to $nextFingerprint. Both identities remain active temporarily; revoke the previous one after the replacement has activated and its relay credential is provisioned."
        )
        store.saveRecord(record)
        if (ownerFingerprint == localFingerprint) {
            try {
                createSignedDeviceRoster()
            } catch (exception: IOException) {
                throw IOException("The rotation was verified and saved, but publishing the new roster failed. Retry roster publication; the old identity remains trusted.", exception)
            }
        }
        return "Verified key continuity from $previousFingerprint to $nextFingerprint. The replacement card is trusted and both identities remain active until the new device activates; a newer owner-signed roster was published where this installation is the owner."
    }

    @Synchronized
    @Throws(IOException::class)
    fun revokeLostDevice(fingerprint: String, adminToken: String): String {
        if (!validFingerprint(fingerprint)) {
            throw IOException("Target fingerprint must be a full lowercase SHA-256 hex digest.")
        }
        val record = requireRecord()
        var relayStatus = "FAILED: Relay administrator request was not completed."
        val relayResult = try {
            relayClient(record).revokeMemberCredential(adminToken, fingerprint)
        } catch (exception: Exception) {
            relayStatus = "FAILED: " + (exception.message ?: "The relay did not confirm credential revocation.")
            null
        }

        if (relayResult != null) {
            relayStatus = if (relayResult.alreadyRevoked) {
                "The relay member credential was already revoked."
            } else {
                "The relay member credential was revoked."
            }
            try {
                appendRosterHistory(
                    record,
                    if (relayResult.alreadyRevoked) "relay_member_already_revoked" else "relay_member_revoked",
                    fingerprint,
                    "A user-supplied administrator token was used for selective relay-member revocation. The administrator token was not stored."
                )
                store.saveRecord(record)
            } catch (exception: IOException) {
                relayStatus += " The relay confirmed this action, but its local audit event could not be persisted."
            }
        } else {
            try {
                appendRosterHistory(
                    record,
                    "relay_member_revocation_failed",
                    fingerprint,
                    "Selective relay-member revocation failed. The administrator token was not stored."
                )
                store.saveRecord(record)
            } catch (_: IOException) {
                relayStatus += " The failed remote attempt could not be recorded locally."
            }
        }

        val localStatus = try {
            revokeTrustedPeerAndPublishRoster(fingerprint)
        } catch (exception: Exception) {
            "Local trust/roster action did not fully complete: " +
                (exception.message ?: "local revocation could not be confirmed.")
        }
        return "Remote relay credential: $relayStatus\nLocal trust and signed roster: $localStatus"
    }

    @Synchronized
    @Throws(IOException::class)
    fun rosterChangeHistory(): org.json.JSONArray {
        val record = requireRecord()
        validateLocalRecord(record)
        return org.json.JSONArray(record.optJSONArray(KEY_ROSTER_HISTORY)?.toString() ?: "[]")
    }

    private fun appendRosterHistory(
        record: JSONObject,
        type: String,
        fingerprint: String?,
        detail: String,
        revision: Long = record.optLong(KEY_ROSTER_REVISION, 0L)
    ) {
        val history = record.optJSONArray(KEY_ROSTER_HISTORY) ?: org.json.JSONArray()
        history.put(
            JSONObject()
                .put("timestamp_unix", System.currentTimeMillis() / 1000L)
                .put("type", type)
                .put("device_fingerprint", fingerprint ?: JSONObject.NULL)
                .put("detail", detail)
                .put("roster_revision", revision.coerceAtLeast(0L))
        )
        while (history.length() > MAX_ROSTER_HISTORY_EVENTS) history.remove(0)
        record.put(KEY_ROSTER_HISTORY, history)
    }

    private fun rosterMember(
        fingerprint: String,
        card: JSONObject?,
        status: String,
        addedAtUnix: Long,
        revokedAtUnix: Long?
    ): JSONObject = JSONObject()
        .put("fingerprint_sha256", fingerprint)
        .put("card", card ?: JSONObject.NULL)
        .put("status", status)
        .put("added_at_unix", addedAtUnix)
        .put("revoked_at_unix", revokedAtUnix ?: JSONObject.NULL)

    private fun validFingerprint(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

    private fun sameDeviceCard(left: JSONObject, right: JSONObject): Boolean {
        val fields = listOf(
            "protocol_version", "device_id", "key_epoch", "signing_public_key_hex",
            "encryption_public_key_hex", "fingerprint_sha256"
        )
        return fields.all { left.optString(it) == right.optString(it) }
    }

    private fun isRosterMemberActive(record: JSONObject, fingerprint: String): Boolean {
        if (!record.has(KEY_DEVICE_ROSTER)) return true
        val roster = record.optJSONObject(KEY_DEVICE_ROSTER)
            ?: throw IOException("Stored signed device roster is malformed.")
        val members = roster.optJSONObject("unsigned")?.optJSONArray("members")
            ?: throw IOException("Stored signed device roster has no members.")
        for (index in 0 until members.length()) {
            val member = members.optJSONObject(index) ?: continue
            if (member.optString("fingerprint_sha256") == fingerprint) {
                return member.optString("status") == "active"
            }
        }
        return false
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
        validateLocalRecord(record)
        val rosterSpace = record.optJSONObject(KEY_DEVICE_ROSTER)
            ?.optJSONObject("unsigned")?.optString("space_id", "")
        if (!rosterSpace.isNullOrEmpty() && rosterSpace != spaceId) {
            throw IOException("Relay space ID cannot change while a signed roster is pinned.")
        }
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
        validateLocalRecord(record)
        val localCard = JSONObject(record.getString(KEY_CARD_JSON))
        val verifiedReply = parseNative(bridge.nativeVerifyIdentityCard(recipientCardJson))
        val recipientCard = verifiedReply.getJSONObject("card")
        val fingerprint = verifiedReply.getString("fingerprint_sha256")
        if (!isRosterMemberActive(record, fingerprint)) {
            throw IOException("Recipient is not active in the verified signed roster. Import a newer roster before sending.")
        }
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
        validateLocalRecord(record)
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
            if (!isRosterMemberActive(record, senderFingerprint)) {
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
                StrictJsonKeyScanner.validate(payloadJson, "Received sync profile")
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
        if (record.optBoolean(KEY_OWNER_ROTATION_HANDOFF_PENDING, false)) {
            throw IOException("Complete the owner-key handoff before exporting recovery. The recovery bundle does not contain the saved public transition package.")
        }
        if (record.has(KEY_PENDING_KEY_ROTATION)) {
            throw IOException("Finish the staged key rotation before exporting recovery. The recovery bundle contains only the currently active identity.")
        }
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
        if (store.loadRecord()?.optBoolean(KEY_OWNER_ROTATION_HANDOFF_PENDING, false) == true) {
            throw IOException("Complete the owner-key handoff before restoring recovery. Replacing the protected record would discard the saved transition package.")
        }
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
        val restored = newRecord(
            localPassphrase,
            response.getString("recovery_bundle_base64"),
            response.getJSONObject("card").toString()
        )
        appendRosterHistory(
            restored,
            "recovery_identity_restored",
            response.getJSONObject("card").optString("fingerprint_sha256"),
            "Restored the same long-term cryptographic identity into a clean local record. Relay configuration and trust history were reset; this does not revoke the previous installation."
        )
        return restored
    }

    @Synchronized
    @Throws(IOException::class)
    fun commitRecoveryImport(importedRecord: JSONObject) {
        if (store.loadRecord()?.optBoolean(KEY_OWNER_ROTATION_HANDOFF_PENDING, false) == true) {
            throw IOException("Owner-key handoff is still pending. Copy the saved transition and confirm the handoff before replacing this protected record.")
        }
        // Recovery import begins with a clean local trust/configuration state.
        store.saveRecord(importedRecord, replaceMissingKeystoreKey = true)
    }

    private fun validatePeerCardJson(cardJson: String) {
        val bytes = cardJson.toByteArray(StandardCharsets.UTF_8)
        try {
            if (cardJson.isBlank() || bytes.isEmpty() || bytes.size > MAX_CARD_JSON_BYTES) {
                throw IOException("Paste a complete public device card under 32 KiB.")
            }
            StrictJsonKeyScanner.validate(cardJson, "Peer device card")
        } finally {
            bytes.fill(0)
        }
    }

    private fun relayClient(record: JSONObject): SyncRelayClient {
        val url = record.optString(KEY_RELAY_URL, "")
        val space = record.optString(KEY_SPACE_ID, "")
        val capability = record.optString(KEY_CAPABILITY, "")
        if (url.isBlank() || space.isBlank() || capability.isBlank()) {
            throw IOException("Save a valid HTTPS relay URL, space ID and capability first.")
        }
        return try {
            val localCard = JSONObject(record.getString(KEY_CARD_JSON))
            SyncRelayClient(
                url,
                space,
                capability,
                localCard.getString("fingerprint_sha256")
            ) { method, pathAndQuery, timestamp, nonce, body ->
                parseNative(
                    bridge.nativeSignRelayRequest(
                        record.getString(KEY_BUNDLE_BASE64),
                        record.getString(KEY_LOCAL_PASSPHRASE),
                        method,
                        pathAndQuery,
                        timestamp,
                        nonce,
                        body
                    )
                ).getString("signature_hex")
            }
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
        if (record.has(KEY_PENDING_KEY_ROTATION)) {
            val pending = record.optJSONObject(KEY_PENDING_KEY_ROTATION)
                ?: throw IOException("Staged key rotation is malformed.")
            val previousFingerprint = pending.optString("previous_fingerprint", "")
            val nextCard = pending.optJSONObject("next_card")
                ?: throw IOException("Staged key rotation omitted its replacement card.")
            val rotation = pending.optJSONObject("rotation_json")
                ?: throw IOException("Staged key rotation omitted its signed transition.")
            if (previousFingerprint != stored.optString("fingerprint_sha256")) {
                throw IOException("Staged key rotation predecessor does not match the local identity.")
            }
            val verifiedRotation = parseNative(
                bridge.nativeVerifyKeyRotation(stored.toString(), rotation.toString(), System.currentTimeMillis() / 1000L)
            ).getJSONObject("next_card")
            if (!sameDeviceCard(verifiedRotation, nextCard)) {
                throw IOException("Staged key rotation signature does not match its replacement card.")
            }
            val nextBundle = pending.optString("next_bundle_base64", "")
            val nextPassphrase = pending.optString("next_local_passphrase", "")
            if (nextBundle.isBlank() || nextPassphrase.isBlank()) {
                throw IOException("Staged key rotation is missing its encrypted replacement identity.")
            }
            val nextIdentity = parseNative(bridge.nativeRestoreIdentity(nextBundle, nextPassphrase)).getJSONObject("card")
            if (!sameDeviceCard(nextIdentity, nextCard)) {
                throw IOException("Staged replacement private bundle does not match its signed card.")
            }
        }
        if (record.has(KEY_DEVICE_ROSTER)) {
            val owner = record.optString(KEY_ROSTER_OWNER, "")
            val revision = record.optLong(KEY_ROSTER_REVISION, 0L)
            if (!validFingerprint(owner) || revision < 1L) {
                throw IOException("Stored signed roster metadata is incomplete.")
            }
            val rosterJson = record.optJSONObject(KEY_DEVICE_ROSTER)?.toString()
                ?: throw IOException("Stored signed roster is malformed.")
            val verified = parseNative(
                bridge.nativeVerifyDeviceRoster(rosterJson, owner, revision - 1L, System.currentTimeMillis() / 1000L)
            ).getJSONObject("roster")
            val unsigned = verified.getJSONObject("unsigned")
            if (unsigned.getLong("revision") != revision ||
                unsigned.getJSONObject("owner_card").optString("fingerprint_sha256") != owner
            ) throw IOException("Stored roster signature or owner/revision pin does not match.")
            val configuredSpace = record.optString(KEY_SPACE_ID, "")
            if (configuredSpace.isNotEmpty() && configuredSpace != unsigned.optString("space_id")) {
                throw IOException("Stored signed roster belongs to a different relay space.")
            }
            val members = unsigned.getJSONArray("members")
            var localMemberFound = false
            for (index in 0 until members.length()) {
                val member = members.getJSONObject(index)
                if (member.optString("fingerprint_sha256") == stored.optString("fingerprint_sha256")) {
                    val card = member.optJSONObject("card")
                    if (member.optString("status") != "active" || card == null || !sameDeviceCard(card, stored)) {
                        throw IOException("Stored signed roster does not authorize this local identity.")
                    }
                    localMemberFound = true
                    break
                }
            }
            if (!localMemberFound) throw IOException("Stored signed roster omits the local identity.")
        } else if (record.has(KEY_ROSTER_OWNER) || record.has(KEY_ROSTER_REVISION)) {
            throw IOException("Stored roster pin exists without its signed roster.")
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
            .put(KEY_TRUSTED_ADDED_AT, JSONObject())
            .put(KEY_REVOKED_FINGERPRINTS, JSONObject())
            .put(KEY_REVOKED_CARDS, JSONObject())
            .put(KEY_ROSTER_HISTORY, org.json.JSONArray())
            .put(KEY_ROSTER_PUBLISH_PENDING, false)
            .put(KEY_NEXT_SEQUENCE, 1L)
            .put(KEY_CURSOR, 0L)

    private fun parseNative(value: String): JSONObject =
        parseNativeSyncResponse(value)

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
        private const val MAX_ROSTER_MEMBERS = 128
        private const val MAX_ROSTER_JSON_BYTES = 256 * 1024
        private const val MAX_ROTATION_PACKAGE_BYTES = 64 * 1024
        private const val MAX_OWNER_ROTATION_PACKAGE_BYTES = 512 * 1024
        private const val MAX_ROSTER_HISTORY_EVENTS = 256
        private const val OWNER_ROTATION_PACKAGE_FORMAT = "privacage-owner-key-rotation-package-v1"
        private const val MAX_ROSTERS_PER_PULL = 25
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
        private const val KEY_TRUSTED_ADDED_AT = "trusted_added_at"
        private const val KEY_REVOKED_FINGERPRINTS = "revoked_fingerprints"
        private const val KEY_REVOKED_CARDS = "revoked_cards"
        private const val KEY_DEVICE_ROSTER = "signed_device_roster"
        private const val KEY_ROSTER_OWNER = "roster_owner_fingerprint"
        private const val KEY_ROSTER_REVISION = "roster_revision"
        private const val KEY_ROSTER_HISTORY = "roster_change_history"
        private const val KEY_ROSTER_PUBLISH_PENDING = "roster_publish_pending"
        private const val KEY_PENDING_KEY_ROTATION = "pending_key_rotation"
        private const val KEY_OWNER_ROTATION_PACKAGE_JSON = "last_owner_key_rotation_package_json"
        private const val KEY_OWNER_ROTATION_HANDOFF_PENDING = "owner_key_rotation_handoff_pending"
        private const val KEY_NEXT_SEQUENCE = "next_sequence"
        private const val KEY_CURSOR = "relay_cursor"
        private const val KEY_PENDING_PROFILE = "pending_profile_json"
        private const val KEY_PENDING_SENDER = "pending_sender_fingerprint"
    }
}
