package org.privacage.android.sync

import org.json.JSONException
import org.json.JSONObject
import org.privacage.android.StrictJsonKeyScanner
import java.io.IOException
import java.nio.charset.StandardCharsets

/**
 * Bounds and strictly parses an opaque relay packet before Android's JSONObject parser.
 * It does not authenticate the packet; the native cryptographic bridge still must do that.
 */
internal object SyncPacketJsonValidator {
    const val MAX_PACKET_JSON_BYTES = 3 * 1024 * 1024

    @Throws(IOException::class)
    fun parse(packetJson: String): JSONObject {
        if (
            packetJson.isEmpty() ||
            packetJson.length > MAX_PACKET_JSON_BYTES ||
            packetJson.toByteArray(StandardCharsets.UTF_8).size > MAX_PACKET_JSON_BYTES
        ) {
            throw IOException("Inbound sync packet is empty or exceeds the 3 MiB JSON limit.")
        }
        StrictJsonKeyScanner.validate(packetJson, "Inbound encrypted sync packet")
        return try {
            JSONObject(packetJson)
        } catch (exception: JSONException) {
            throw IOException("Inbound encrypted sync packet is not a JSON object.", exception)
        }
    }
}
