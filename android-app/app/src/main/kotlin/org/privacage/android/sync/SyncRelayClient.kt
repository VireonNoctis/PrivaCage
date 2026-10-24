package org.privacage.android.sync

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

internal data class RelayedMessage(val cursor: Long, val messageId: String, val packetJson: String)
internal data class RelayPage(val nextCursor: Long, val messages: List<RelayedMessage>)
internal data class RelayedRoster(
    val revision: Long,
    val ownerFingerprint: String,
    val rosterJson: String,
    val insertedAtUnix: Long
)
internal data class RosterPage(val nextRevision: Long, val rosters: List<RelayedRoster>)
internal data class RelayMemberRevocationResult(val alreadyRevoked: Boolean)

/**
 * HTTPS-only client for the opaque relay API. Redirects are not followed because a redirect
 * could send the bearer capability to another origin.
 */
internal class SyncRelayClient(
    baseUrl: String,
    private val spaceId: String,
    private val capabilityToken: String,
    private val deviceFingerprint: String,
    private val requestSigner: (String, String, Long, String, String) -> String
) {
    private val baseUrl = validateBaseUrl(baseUrl)

    init {
        require(isValidSpaceId(spaceId)) { "Space ID must be 8–80 ASCII letters, digits, underscores, or hyphens." }
        require(isValidCapability(capabilityToken)) { "Space capability must be 64 lowercase hexadecimal characters." }
        require(isValidFingerprint(deviceFingerprint)) { "Device fingerprint must be a full lowercase SHA-256 digest." }
    }

    @Throws(IOException::class)
    fun upload(messageId: String, packetJson: String) {
        require(isValidMessageId(messageId)) { "Sync message ID is invalid." }
        val payload = packetJson.toByteArray(StandardCharsets.UTF_8)
        if (payload.isEmpty() || payload.size > MAX_REQUEST_BYTES) {
            payload.fill(0)
            throw IOException("Encrypted sync packet exceeds the relay's 2 MiB request limit.")
        }
        try {
            request("PUT", "/v1/spaces/$spaceId/messages/$messageId", payload,
                setOf(HttpURLConnection.HTTP_CREATED), 1024)
        } finally {
            payload.fill(0)
        }
    }

    @Throws(IOException::class)
    fun publishRoster(rosterJson: String) {
        val payload = rosterJson.toByteArray(StandardCharsets.UTF_8)
        if (payload.isEmpty() || payload.size > MAX_ROSTER_BYTES) {
            payload.fill(0)
            throw IOException("Signed roster exceeds the relay's 256 KiB limit.")
        }
        try {
            val response = request(
                "PUT",
                "/v1/spaces/$spaceId/roster",
                payload,
                setOf(HttpURLConnection.HTTP_CREATED, HttpURLConnection.HTTP_NO_CONTENT),
                1024
            )
            response.fill(0)
        } finally {
            payload.fill(0)
        }
    }

    /**
     * Selectively revokes one enrolled member using the relay administrator token.
     * The administrator token is accepted per call and is never retained by this client.
     * Member-mode is checked first because deleting a member row does not disable a legacy
     * shared capability.
     */
    @Throws(IOException::class)
    fun revokeMemberCredential(adminToken: String, fingerprint: String): RelayMemberRevocationResult {
        if (!isValidAdminToken(adminToken)) {
            throw IOException("Relay administrator token must be 32–4096 printable ASCII characters without whitespace.")
        }
        if (!isValidFingerprint(fingerprint)) {
            throw IOException("Target fingerprint must be a full lowercase SHA-256 hex digest.")
        }

        val membersBytes = request(
            "GET",
            "/v1/spaces/$spaceId/members",
            null,
            setOf(HttpURLConnection.HTTP_OK),
            MAX_RESPONSE_BYTES,
            authorizationToken = adminToken,
            signAsDevice = false
        )
        val currentState = try {
            parseMemberRevocationState(String(membersBytes, StandardCharsets.UTF_8), fingerprint)
        } finally {
            membersBytes.fill(0)
        }
        if (currentState.alreadyRevoked) return currentState

        val response = request(
            "DELETE",
            "/v1/spaces/$spaceId/members/$fingerprint",
            null,
            setOf(HttpURLConnection.HTTP_NO_CONTENT),
            1024,
            authorizationToken = adminToken,
            signAsDevice = false
        )
        response.fill(0)
        return RelayMemberRevocationResult(alreadyRevoked = false)
    }

    @Throws(IOException::class)
    fun fetchRostersAfter(afterRevision: Long, limit: Int = DEFAULT_ROSTER_PAGE_SIZE): RosterPage {
        require(afterRevision >= 0) { "Roster revision cannot be negative." }
        require(limit in 1..MAX_ROSTER_PAGE_SIZE) { "Roster page size must be from 1 to $MAX_ROSTER_PAGE_SIZE." }
        val bytes = request(
            "GET",
            "/v1/spaces/$spaceId/rosters?after_revision=$afterRevision&limit=$limit",
            null,
            setOf(HttpURLConnection.HTTP_OK),
            MAX_RESPONSE_BYTES
        )
        try {
            val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
            val nextRevision = json.optLong("next_revision", -1L)
            if (nextRevision < afterRevision) throw IOException("Relay returned a backward roster revision.")
            val rawRosters = json.optJSONArray("rosters")
                ?: throw IOException("Relay response omitted the roster history array.")
            if (rawRosters.length() > limit) throw IOException("Relay returned more roster revisions than requested.")
            val rosters = ArrayList<RelayedRoster>(rawRosters.length())
            var previousRevision = afterRevision
            for (index in 0 until rawRosters.length()) {
                val item = rawRosters.optJSONObject(index)
                    ?: throw IOException("Relay returned a malformed roster history entry.")
                val revision = item.optLong("revision", -1L)
                val ownerFingerprint = item.optString("owner_fingerprint", "")
                val roster = item.optJSONObject("roster")
                    ?: throw IOException("Relay roster entry omitted its signed roster.")
                val unsigned = roster.optJSONObject("unsigned")
                val rosterRevision = unsigned?.optLong("revision", -1L) ?: -1L
                val rosterOwner = unsigned?.optJSONObject("owner_card")
                    ?.optString("fingerprint_sha256", "").orEmpty()
                if (revision <= previousRevision || rosterRevision != revision ||
                    !isValidFingerprint(ownerFingerprint) || ownerFingerprint != rosterOwner
                ) {
                    throw IOException("Relay roster history contains inconsistent revision or owner metadata.")
                }
                previousRevision = revision
                rosters += RelayedRoster(
                    revision,
                    ownerFingerprint,
                    roster.toString(),
                    item.optLong("inserted_at_unix", 0L)
                )
            }
            if (rosters.isNotEmpty() && nextRevision != rosters.last().revision) {
                throw IOException("Relay returned an inconsistent roster cursor.")
            }
            if (rosters.isEmpty() && nextRevision != afterRevision) {
                throw IOException("Relay advanced the roster cursor without returning a roster.")
            }
            return RosterPage(nextRevision, rosters)
        } catch (exception: IOException) {
            throw exception
        } catch (exception: Exception) {
            throw IOException("Relay returned an invalid signed roster history page.", exception)
        } finally {
            bytes.fill(0)
        }
    }

    @Throws(IOException::class)
    fun fetchAfter(cursor: Long, limit: Int = 1): RelayPage {
        require(cursor >= 0) { "Relay cursor cannot be negative." }
        require(limit in 1..MAX_PAGE_SIZE) { "Relay page size must be from 1 to $MAX_PAGE_SIZE." }
        val bytes = request(
            "GET",
            "/v1/spaces/$spaceId/messages?after=$cursor&limit=$limit",
            null,
            setOf(HttpURLConnection.HTTP_OK),
            MAX_RESPONSE_BYTES
        )
        try {
            val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
            val nextCursor = json.optLong("next_cursor", -1L)
            if (nextCursor < cursor) throw IOException("Relay returned a backward cursor.")
            val rawMessages = json.optJSONArray("messages")
                ?: throw IOException("Relay response omitted the messages array.")
            if (rawMessages.length() > limit) throw IOException("Relay returned more messages than requested.")
            val messages = ArrayList<RelayedMessage>(rawMessages.length())
            for (index in 0 until rawMessages.length()) {
                val item = rawMessages.optJSONObject(index)
                    ?: throw IOException("Relay response contains a malformed message.")
                val messageCursor = item.optLong("cursor", -1L)
                val messageId = item.optString("message_id", "")
                val payloadHex = item.optString("payload_hex", "")
                if (messageCursor <= cursor || messageCursor > nextCursor ||
                    !isValidMessageId(messageId) || payloadHex.isEmpty() ||
                    payloadHex.length % 2 != 0 || payloadHex.length > MAX_REQUEST_BYTES * 2 ||
                    payloadHex.any { it !in '0'..'9' && it !in 'a'..'f' }
                ) {
                    throw IOException("Relay response contains invalid message metadata.")
                }
                val payload = decodeHex(payloadHex)
                val packetJson = try {
                    StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(payload))
                        .toString()
                } catch (exception: Exception) {
                    throw IOException("Relay packet is not valid UTF-8 JSON.", exception)
                } finally {
                    payload.fill(0)
                }
                try {
                    JSONObject(packetJson)
                } catch (exception: Exception) {
                    throw IOException("Relay packet is not a JSON object.", exception)
                }
                messages += RelayedMessage(messageCursor, messageId, packetJson)
            }
            if (messages.isNotEmpty() && nextCursor != messages.last().cursor) {
                throw IOException("Relay returned an inconsistent pagination cursor.")
            }
            if (messages.isEmpty() && nextCursor != cursor) {
                throw IOException("Relay advanced a cursor without returning a message.")
            }
            return RelayPage(nextCursor, messages)
        } catch (exception: IOException) {
            throw exception
        } catch (exception: Exception) {
            throw IOException("Relay returned an invalid message page.", exception)
        } finally {
            bytes.fill(0)
        }
    }

    private fun request(
        method: String,
        path: String,
        body: ByteArray?,
        expectedStatuses: Set<Int>,
        maxResponseBytes: Int,
        authorizationToken: String = capabilityToken,
        signAsDevice: Boolean = true
    ): ByteArray {
        val url = URL(baseUrl + path)
        val connection = (url.openConnection() as? HttpURLConnection)
            ?: throw IOException("Could not open relay connection.")
        connection.instanceFollowRedirects = false
        connection.requestMethod = method
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS
        connection.useCaches = false
        connection.setRequestProperty("Authorization", "Bearer $authorizationToken")
        if (signAsDevice) {
            val timestamp = System.currentTimeMillis() / 1000L
            val nonce = randomNonce()
            val requestBodyText = body?.let { String(it, StandardCharsets.UTF_8) } ?: ""
            val signature = requestSigner(method, path, timestamp, nonce, requestBodyText)
            connection.setRequestProperty("X-PCAGE-Device-Fingerprint", deviceFingerprint)
            connection.setRequestProperty("X-PCAGE-Timestamp", timestamp.toString())
            connection.setRequestProperty("X-PCAGE-Nonce", nonce)
            connection.setRequestProperty("X-PCAGE-Signature", signature)
        }
        connection.setRequestProperty("Accept", "application/json")
        connection.setRequestProperty("Cache-Control", "no-store")
        connection.setRequestProperty("Pragma", "no-cache")
        if (body != null) {
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setFixedLengthStreamingMode(body.size)
        }
        try {
            if (body != null) {
                connection.outputStream.use { output ->
                    output.write(body)
                    output.flush()
                }
            }
            val status = connection.responseCode
            if (status !in expectedStatuses) {
                throw IOException(
                    when (status) {
                        in 300..399 -> "Relay attempted a redirect; credentials were not forwarded."
                        HttpURLConnection.HTTP_UNAUTHORIZED,
                        HttpURLConnection.HTTP_FORBIDDEN -> if (signAsDevice) {
                            "Relay rejected the space capability."
                        } else {
                            "Relay rejected the administrator token or denied this member operation."
                        }
                        HttpURLConnection.HTTP_CONFLICT -> "Relay reported a conflicting operation."
                        HttpURLConnection.HTTP_BAD_REQUEST -> "Relay rejected the request format."
                        507 -> "Relay space is full."
                        else -> "Relay request failed with HTTP $status."
                    }
                )
            }
            if (status == HttpURLConnection.HTTP_NO_CONTENT) return ByteArray(0)
            return connection.inputStream.use { readLimited(it, maxResponseBytes) }
        } finally {
            connection.disconnect()
        }
    }

    private fun readLimited(input: java.io.InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        try {
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                if (output.size() > maxBytes - count) throw IOException("Relay response exceeds the local safety limit.")
                output.write(buffer, 0, count)
            }
            return output.toByteArray()
        } finally {
            buffer.fill(0)
        }
    }

    private fun randomNonce(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return try {
            bytes.joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
        } finally {
            bytes.fill(0)
        }
    }

    private fun decodeHex(value: String): ByteArray {
        val output = ByteArray(value.length / 2)
        for (index in output.indices) {
            val start = index * 2
            val parsed = value.substring(start, start + 2).toIntOrNull(16)
                ?: throw IOException("Relay payload contains invalid hexadecimal bytes.")
            output[index] = parsed.toByte()
        }
        return output
    }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 30_000
        private const val MAX_REQUEST_BYTES = 3 * 1024 * 1024
        private const val MAX_RESPONSE_BYTES = 5_000_000
        private const val MAX_PAGE_SIZE = 100
        private const val MAX_ROSTER_BYTES = 256 * 1024
        private const val MAX_ROSTER_PAGE_SIZE = 25
        private const val DEFAULT_ROSTER_PAGE_SIZE = 25

        fun validateBaseUrl(value: String): String {
            val trimmed = value.trim()
            val uri = try {
                URI(trimmed)
            } catch (exception: Exception) {
                throw IllegalArgumentException("Enter a valid HTTPS relay URL.", exception)
            }
            require(uri.scheme.equals("https", ignoreCase = true) &&
                !uri.host.isNullOrBlank() &&
                uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null
            ) { "Relay URL must use HTTPS and must not contain credentials, a query, or a fragment." }
            require(uri.port == -1 || uri.port in 1..65535) { "Relay URL port is invalid." }
            val path = uri.rawPath.orEmpty().trimEnd('/')
            require(path.none { it == '\\' || it.isWhitespace() }) { "Relay URL path contains unsupported characters." }
            return buildString {
                append("https://")
                append(uri.rawAuthority)
                if (path.isNotEmpty()) append(path)
            }
        }

        fun isValidSpaceId(value: String): Boolean =
            value.length in 8..80 && value.all {
                it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
            }

        fun isValidCapability(value: String): Boolean =
            value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

        fun isValidAdminToken(value: String): Boolean =
            value.length in 32..4096 && value.all { it.code in 0x21..0x7e }

        internal fun parseMemberRevocationState(
            responseJson: String,
            targetFingerprint: String
        ): RelayMemberRevocationResult {
            if (!isValidFingerprint(targetFingerprint)) {
                throw IOException("Target fingerprint must be a full lowercase SHA-256 hex digest.")
            }
            val response = try {
                JSONObject(responseJson)
            } catch (exception: Exception) {
                throw IOException("Relay administrator response was not valid JSON.", exception)
            }
            if (!response.has("member_mode") || response.isNull("member_mode")) {
                throw IOException("Relay administrator response omitted the member-mode state.")
            }
            val memberMode = try {
                response.getBoolean("member_mode")
            } catch (exception: Exception) {
                throw IOException("Relay administrator response contains an invalid member-mode state.", exception)
            }
            if (!memberMode) {
                throw IOException(
                    "Per-device member mode is not active. Selective revocation would not disable the legacy shared capability; rotate that capability through the relay administrator first."
                )
            }
            val members = response.optJSONArray("members")
                ?: throw IOException("Relay administrator response omitted the member list.")
            var targetFound = false
            var targetRevokedAt: Long? = null
            for (index in 0 until members.length()) {
                val member = members.optJSONObject(index)
                    ?: throw IOException("Relay administrator response contains a malformed member.")
                val fingerprint = member.optString("fingerprint", "")
                if (!isValidFingerprint(fingerprint)) {
                    throw IOException("Relay administrator response contains an invalid member fingerprint.")
                }
                if (fingerprint != targetFingerprint) continue
                if (targetFound) {
                    throw IOException("Relay administrator response contains a duplicate target member.")
                }
                targetFound = true
                if (!member.has("revoked_at_unix")) {
                    throw IOException("Relay administrator response omitted the target revocation state.")
                }
                if (!member.isNull("revoked_at_unix")) {
                    val revokedAt = member.optLong("revoked_at_unix", -1L)
                    if (revokedAt <= 0L) {
                        throw IOException("Relay administrator response contains an invalid revocation timestamp.")
                    }
                    targetRevokedAt = revokedAt
                }
            }
            if (!targetFound) {
                throw IOException("This fingerprint has no registered relay member credential in this space.")
            }
            return RelayMemberRevocationResult(alreadyRevoked = targetRevokedAt != null)
        }

        private fun isValidFingerprint(value: String): Boolean =
            value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

        private fun isValidMessageId(value: String): Boolean =
            value.length == 32 && value.all { it in '0'..'9' || it in 'a'..'f' }
    }
}
