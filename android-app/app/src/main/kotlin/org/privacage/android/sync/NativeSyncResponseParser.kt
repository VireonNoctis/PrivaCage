package org.privacage.android.sync

import org.json.JSONObject
import org.privacage.android.StrictJsonKeyScanner
import java.nio.charset.StandardCharsets

/**
 * Parses the Rust/JNI bridge response before any caller consumes fields.
 * Success payload fields vary by operation, but the status itself is never coercible.
 */
internal fun parseNativeSyncResponse(value: String): JSONObject {
    if (
        value.isEmpty() ||
        value.length > MAX_NATIVE_SYNC_RESPONSE_BYTES ||
        value.toByteArray(StandardCharsets.UTF_8).size > MAX_NATIVE_SYNC_RESPONSE_BYTES
    ) {
        throw SyncBridgeFailure("Native sync bridge returned an empty or oversized response.")
    }
    try {
        StrictJsonKeyScanner.validate(value, "Native sync bridge response")
        val response = JSONObject(value)
        val ok = response.opt("ok") as? Boolean
            ?: throw SyncBridgeFailure("Native sync bridge response omitted its JSON boolean status.")
        if (!ok) {
            val keys = response.keys().asSequence().toSet()
            if (keys != setOf("ok", "error")) {
                throw SyncBridgeFailure("Native sync bridge returned an invalid error response schema.")
            }
            val error = response.opt("error") as? String
                ?: throw SyncBridgeFailure("Native sync bridge returned an invalid error message.")
            if (error.isBlank() || error.length > MAX_NATIVE_SYNC_ERROR_LENGTH || error.any(Char::isISOControl)) {
                throw SyncBridgeFailure("Native sync bridge returned an invalid error message.")
            }
            throw SyncBridgeFailure(error)
        }
        if (response.has("error")) {
            throw SyncBridgeFailure("Native sync bridge success response unexpectedly included an error field.")
        }
        return response
    } catch (failure: SyncBridgeFailure) {
        throw failure
    } catch (exception: Exception) {
        throw SyncBridgeFailure("Native sync bridge returned malformed JSON.")
    }
}

internal const val MAX_NATIVE_SYNC_RESPONSE_BYTES = 2 * 1024 * 1024
private const val MAX_NATIVE_SYNC_ERROR_LENGTH = 2_048
