package org.privacage.android.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeSyncResponseParserTest {
    @Test
    fun acceptsStrictSuccessStatusAndOperationSpecificFields() {
        val response = parseNativeSyncResponse(
            """{"ok":true,"card":{"device_id":"device-1"},"recovery_bundle_base64":"AA=="}"""
        )
        assertEquals(true, response.get("ok"))
        assertEquals("device-1", response.getJSONObject("card").getString("device_id"))
    }

    @Test
    fun rejectsMissingCoercibleAndDuplicatedStatusFields() {
        assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"card":{}}""")
        }
        assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"ok":"true","card":{}}""")
        }
        assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"ok":1,"card":{}}""")
        }
        assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"ok":true,"ok":false}""")
        }
        assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"ok":true,"o\u006b":false}""")
        }
    }

    @Test
    fun errorResponsesRequireExactStringSchemaAndBoundedMessage() {
        val error = assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"ok":false,"error":"packet rejected"}""")
        }
        assertEquals("packet rejected", error.message)

        assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"ok":false,"error":17}""")
        }
        assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"ok":false,"error":"invalid","extra":"unexpected"}""")
        }
        assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"ok":true,"error":"should-not-be-here"}""")
        }
    }

    @Test
    fun rejectsMalformedAndOversizedResponseBeforeObjectConstruction() {
        assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse("""{"ok":tru}""")
        }
        val failure = assertThrows(SyncBridgeFailure::class.java) {
            parseNativeSyncResponse(" ".repeat(MAX_NATIVE_SYNC_RESPONSE_BYTES + 1))
        }
        assertTrue(failure.message.orEmpty().contains("oversized"))
    }
}
