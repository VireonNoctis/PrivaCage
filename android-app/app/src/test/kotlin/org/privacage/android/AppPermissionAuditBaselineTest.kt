package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.time.Instant

class AppPermissionAuditBaselineTest {
    @Test
    fun missingAndValidPreferenceValuesAreNotClassifiedAsCorrupt() {
        val missing = AppPermissionAudit.readBaselinePreference { null }
        assertEquals(null, missing.value)
        assertEquals(false, missing.unreadable)
        assertEquals(null, missing.warning)

        val valid = AppPermissionAudit.readBaselinePreference { """{"schema_version":1,"packages":{}}""" }
        assertEquals(false, valid.unreadable)
        assertEquals(null, valid.warning)
        assertTrue(valid.value.orEmpty().contains("schema_version"))
    }

    @Test
    fun wrongPreferenceTypeIsMarkedUnreadableForNonDestructiveRecovery() {
        val result = AppPermissionAudit.readBaselinePreference {
            throw ClassCastException("preference was stored as an integer")
        }

        assertEquals(null, result.value)
        assertEquals(true, result.unreadable)
        assertTrue(result.warning.orEmpty().contains("preserved"))
    }

    @Test
    fun acceptsOnlyTheExactBaselineSchema() {
        val snapshot = AppPermissionAudit.decodeBaseline(
            """{"schema_version":1,"packages":{"com.example.app":{"android.permission.CAMERA":true}}}"""
        )

        assertEquals(
            mapOf("com.example.app" to mapOf("android.permission.CAMERA" to true)),
            snapshot.packages
        )
    }

    @Test
    fun rejectsFractionalFutureStringAndBooleanSchemaVersions() {
        val invalidVersions = listOf("1.0", "1.5", "2", "\"1\"", "true", "null")
        for (version in invalidVersions) {
            val json = """{"schema_version":$version,"packages":{}}"""
            assertThrows("schema_version=$version", IOException::class.java) {
                AppPermissionAudit.decodeBaseline(json)
            }
        }
    }

    @Test
    fun rejectsDuplicateBaselineKeysBeforeJSONObjectCanCollapseThem() {
        assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(
                """{"schema_version":1,"schema_version":1,"packages":{}}"""
            )
        }
        assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(
                "{\"schema_version\":1,\"packages\":{},\"packages\":{}}"
            )
        }
    }

    @Test
    fun rejectsUnknownTopLevelFieldsInsteadOfSilentlyIgnoringThem() {
        val exception = assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(
                """{"schema_version":1,"packages":{},"history_complete":true}"""
            )
        }
        assertTrue(exception.message.orEmpty().contains("unsupported top-level fields"))
    }

    @Test
    fun rejectsOversizedBaselineBeforeBuildingJsonObjects() {
        val oversized = " ".repeat(4 * 1024 * 1024 + 1)
        val exception = assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(oversized)
        }
        assertTrue(exception.message.orEmpty().contains("4 MiB safety limit"))
    }

    @Test
    fun rejectsInvalidPackageAndPermissionNameSyntax() {
        assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(
                """{"schema_version":1,"packages":{"com/example.app":{"android.permission.CAMERA":true}}}"""
            )
        }
        assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(
                """{"schema_version":1,"packages":{"com.example.app":{"android..permission.CAMERA":true}}}"""
            )
        }
    }

    @Test
    fun rejectsExcessivePackageAndPerPackagePermissionCounts() {
        val packageEntries = (0..2_000).joinToString(",") { index ->
            "\"org.example.app$index\":{}"
        }
        assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(
                """{"schema_version":1,"packages":{$packageEntries}}"""
            )
        }

        val permissionEntries = (0..256).joinToString(",") { index ->
            "\"android.permission.TEST_$index\":true"
        }
        assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(
                """{"schema_version":1,"packages":{"org.example.app":{$permissionEntries}}}"""
            )
        }
    }


    @Test
    fun writesTimestampedSchemaV2AndRoundTripsTheSnapshot() {
        val capturedAt = Instant.parse("2026-11-01T09:30:00Z")
        val snapshot = org.privacage.audit.PermissionGrantSnapshot(
            mapOf("com.example.app" to mapOf("android.permission.CAMERA" to true))
        )

        val encoded = AppPermissionAudit.encodeBaseline(snapshot, capturedAt)
        val decoded = AppPermissionAudit.decodeBaselineRecord(encoded)

        assertTrue(encoded.contains("\"schema_version\":2"))
        assertTrue(encoded.contains("\"captured_at\":\"2026-11-01T09:30:00Z\""))
        assertEquals(snapshot, decoded.snapshot)
        assertEquals(capturedAt, decoded.capturedAt)
    }

    @Test
    fun readsLegacySchemaV1WithoutInventingACaptureTime() {
        val decoded = AppPermissionAudit.decodeBaselineRecord(
            """{"schema_version":1,"packages":{"com.example.app":{"android.permission.CAMERA":true}}}"""
        )

        assertEquals(
            mapOf("com.example.app" to mapOf("android.permission.CAMERA" to true)),
            decoded.snapshot.packages
        )
        assertEquals(null, decoded.capturedAt)
    }

    @Test
    fun rejectsMalformedOrNonCanonicalCaptureTimestamps() {
        val invalidTimestamps = listOf(
            "not-a-time",
            "2026-11-01T09:30:00+00:00",
            "2026-11-01T09:30:00"
        )
        invalidTimestamps.forEach { timestamp ->
            assertThrows("captured_at=$timestamp", IOException::class.java) {
                AppPermissionAudit.decodeBaselineRecord(
                    """{"schema_version":2,"captured_at":"$timestamp","packages":{}}"""
                )
            }
        }
    }

    @Test
    fun rejectsSnapshotsThatExceedPackageOrPermissionCountLimitsBeforeSerialization() {
        val tooManyPackages = org.privacage.audit.PermissionGrantSnapshot(
            (0..2_000).associate { "org.example.app$it" to emptyMap() }
        )
        assertThrows(IOException::class.java) {
            AppPermissionAudit.encodeBaseline(tooManyPackages, Instant.EPOCH)
        }

        val tooManyPermissions = org.privacage.audit.PermissionGrantSnapshot(
            mapOf("org.example.app" to (0..256).associate { "android.permission.TEST_$it" to true })
        )
        assertThrows(IOException::class.java) {
            AppPermissionAudit.encodeBaseline(tooManyPermissions, Instant.EPOCH)
        }
    }

    @Test
    fun rejectsSnapshotsThatWouldExceedTheFourMibLimitBeforeBuildingJsonTrees() {
        val longPermissionPrefix = "android.permission."
        val permissions = (0 until 10).associate { index ->
            longPermissionPrefix + "A".repeat(234) + index.toString().padStart(2, '0') to true
        }
        val packages = (0 until 2_000).associate { index ->
            "org.example.app$index" to permissions
        }
        assertThrows(IOException::class.java) {
            AppPermissionAudit.encodeBaseline(
                org.privacage.audit.PermissionGrantSnapshot(packages),
                Instant.EPOCH
            )
        }
    }

    @Test
    fun rejectsInvalidNamesWhenEncodingSnapshots() {
        assertThrows(IOException::class.java) {
            AppPermissionAudit.encodeBaseline(
                org.privacage.audit.PermissionGrantSnapshot(mapOf("com/example.app" to emptyMap())),
                Instant.EPOCH
            )
        }
        assertThrows(IOException::class.java) {
            AppPermissionAudit.encodeBaseline(
                org.privacage.audit.PermissionGrantSnapshot(
                    mapOf("com.example.app" to mapOf("android..permission.CAMERA" to true))
                ),
                Instant.EPOCH
            )
        }
    }

    @Test
    fun rejectsWrongTypesAndInvalidPermissionEntries() {
        assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline("""{"schema_version":1,"packages":[]}""")
        }
        assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(
                """{"schema_version":1,"packages":{"com.example.app":{"android.permission.CAMERA":"true"}}}"""
            )
        }
        assertThrows(IOException::class.java) {
            AppPermissionAudit.decodeBaseline(
                """{"schema_version":1,"packages":{"com.example.app":{"":true}}}"""
            )
        }
    }
}
