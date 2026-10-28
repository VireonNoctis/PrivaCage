package org.privacage.android.sync

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidKeystoreIdentityStoreSchemaTest {
    @Test
    fun acceptsOnlyAnExactIntegerVersion() {
        val version = JSONObject("""{"version":1}""").opt("version")
        assertTrue(AndroidKeystoreIdentityStore.hasExactIntegerVersion(version, 1))
    }

    @Test
    fun acceptsKnownOptionalRecordFieldsAndEmptyOptionalSubsets() {
        assertTrue(
            AndroidKeystoreIdentityStore.hasOnlySupportedRecordFields(
                setOf("record_version", "identity_bundle_base64", "pending_profile_json")
            )
        )
        assertTrue(
            AndroidKeystoreIdentityStore.hasOnlySupportedRecordFields(
                setOf("record_version", "identity_bundle_base64", "card_json")
            )
        )
    }

    @Test
    fun rejectsUnknownTopLevelRecordFields() {
        assertFalse(
            AndroidKeystoreIdentityStore.hasOnlySupportedRecordFields(
                setOf("record_version", "identity_bundle_base64", "unreviewed_remote_state")
            )
        )
    }

    @Test
    fun rejectsCoercibleDecimalStringBooleanAndFutureVersions() {
        val unsupported = listOf("1.0", "1.5", "\"1\"", "true", "null", "2")
        for (rawVersion in unsupported) {
            val parsed = JSONObject("""{"version":$rawVersion}""").opt("version")
            assertFalse(
                "Should reject version $rawVersion (parsed as $parsed)",
                AndroidKeystoreIdentityStore.hasExactIntegerVersion(parsed, 1)
            )
        }
    }
}
