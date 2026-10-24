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
                HttpURLConnection.HTTP_CREATED, 1024)
        } finally {
            payload.fill(0)
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
            HttpURLConnection.HTTP_OK,
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
        expectedStatus: Int,
        maxResponseBytes: Int
    ): ByteArray {
        val url = URL(baseUrl + path)
        val connection = (url.openConnection() as? HttpURLConnection)
            ?: throw IOException("Could not open relay connection.")
        connection.instanceFollowRedirects = false
        connection.requestMethod = method
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS
        connection.useCaches = false
        val timestamp = System.currentTimeMillis() / 1000L
        val nonce = randomNonce()
        val requestBodyText = body?.let { String(it, StandardCharsets.UTF_8) } ?: ""
        val signature = requestSigner(method, path, timestamp, nonce, requestBodyText)
        connection.setRequestProperty("Authorization", "Bearer $capabilityToken")
        connection.setRequestProperty("X-PCAGE-Device-Fingerprint", deviceFingerprint)
        connection.setRequestProperty("X-PCAGE-Timestamp", timestamp.toString())
        connection.setRequestProperty("X-PCAGE-Nonce", nonce)
        connection.setRequestProperty("X-PCAGE-Signature", signature)
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
            if (status != expectedStatus) {
                throw IOException(
                    when (status) {
                        in 300..399 -> "Relay attempted a redirect; credentials were not forwarded."
                        HttpURLConnection.HTTP_UNAUTHORIZED,
                        HttpURLConnection.HTTP_FORBIDDEN -> "Relay rejected the space capability."
                        HttpURLConnection.HTTP_CONFLICT -> "Relay already contains this message ID."
                        HttpURLConnection.HTTP_BAD_REQUEST -> "Relay rejected the request format."
                        507 -> "Relay space is full."
                        else -> "Relay request failed with HTTP $status."
                    }
                )
            }
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

        private fun isValidFingerprint(value: String): Boolean =
            value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

        private fun isValidMessageId(value: String): Boolean =
            value.length == 32 && value.all { it in '0'..'9' || it in 'a'..'f' }
    }
}
