package org.privacage.android

import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.time.Instant

class AppPermissionAuditBaselineTest {
    @Test
    fun unresolvedPermissionMetadataIsUnknownRatherThanNonDangerous() {
        assertNull(
            AppPermissionAudit.isDangerousPermission {
                throw PackageManager.NameNotFoundException("permission is not known to this system")
            }
        )
        assertNull(
            AppPermissionAudit.isDangerousPermission {
                throw SecurityException("permission metadata is not visible")
            }
        )
    }

    @Test
    fun permissionClassificationUsesTheBaseProtectionLevel() {
        assertEquals(
            true,
            AppPermissionAudit.isDangerousPermission { PermissionInfo.PROTECTION_DANGEROUS }
        )
        assertEquals(
            false,
            AppPermissionAudit.isDangerousPermission { PermissionInfo.PROTECTION_NORMAL }
        )
    }

    @Test
    fun missingOrMisalignedGrantFlagsRemainUnknown() {
        assertNull(AppPermissionAudit.requestedPermissionGrantState(null, 0))
        assertNull(AppPermissionAudit.requestedPermissionGrantState(intArrayOf(), 0))
        assertNull(AppPermissionAudit.requestedPermissionGrantState(intArrayOf(0), 1))
        assertEquals(
            true,
            AppPermissionAudit.requestedPermissionGrantState(
                intArrayOf(PackageInfo.REQUESTED_PERMISSION_GRANTED),
                0
            )
        )
        assertEquals(false, AppPermissionAudit.requestedPermissionGrantState(intArrayOf(0), 0))
    }

    @Test
    fun anyMissingPermissionEvidenceBlocksBaselineComparison() {
        assertTrue(AppPermissionAudit.isCompleteScan(0, 0, 0))
        assertFalse(AppPermissionAudit.isCompleteScan(1, 0, 0))
        assertFalse(AppPermissionAudit.isCompleteScan(0, 1, 0))
        assertFalse(AppPermissionAudit.isCompleteScan(0, 0, 1))
        assertFalse(AppPermissionAudit.isCompleteScan(0, 0, 0, 1))
    }

    @Test
    fun launcherInventoryMustFitTheSupportedBaselinePackageLimit() {
        assertTrue(AppPermissionAudit.isWithinBaselinePackageLimit(2_000))
        assertFalse(AppPermissionAudit.isWithinBaselinePackageLimit(2_001))
        assertFalse(AppPermissionAudit.isWithinBaselinePackageLimit(-1))
    }

    @Test
    fun declaredPermissionScanningIsBoundedPerPackageAndAcrossTheWholeScan() {
        assertTrue(AppPermissionAudit.permissionDeclarationsFitLimits(512, 0))
        assertFalse(AppPermissionAudit.permissionDeclarationsFitLimits(513, 0))
        assertTrue(AppPermissionAudit.permissionDeclarationsFitLimits(1, 49_999))
        assertTrue(AppPermissionAudit.permissionDeclarationsFitLimits(0, 50_000))
        assertFalse(AppPermissionAudit.permissionDeclarationsFitLimits(1, 50_000))
        assertFalse(AppPermissionAudit.permissionDeclarationsFitLimits(-1, 0))
        assertFalse(AppPermissionAudit.permissionDeclarationsFitLimits(1, -1))
    }

    @Test
    fun baselineMustBeEncodableBeforeComparisonCanProceed() {
        val validSnapshot = org.privacage.audit.PermissionGrantSnapshot(
            mapOf("com.example.app" to mapOf("android.permission.CAMERA" to true))
        )
        val validPreparation = AppPermissionAudit.prepareBaselineForComparison(validSnapshot, Instant.EPOCH)
        assertTrue(validPreparation.encoded.orEmpty().isNotBlank())
        assertEquals(null, validPreparation.failureReason)
        assertTrue(AppPermissionAudit.canCompareBaseline(0, 0, 0, validPreparation))

        val tooManyPackages = org.privacage.audit.PermissionGrantSnapshot(
            (0..2_000).associate { "org.example.app$it" to emptyMap() }
        )
        val rejectedPreparation = AppPermissionAudit.prepareBaselineForComparison(tooManyPackages, Instant.EPOCH)
        assertEquals(null, rejectedPreparation.encoded)
        assertTrue(rejectedPreparation.failureReason.orEmpty().contains("package count"))
        assertFalse(AppPermissionAudit.canCompareBaseline(0, 0, 0, rejectedPreparation))
        assertFalse(AppPermissionAudit.canCompareBaseline(1, 0, 0, validPreparation))
        assertFalse(AppPermissionAudit.canCompareBaseline(0, 0, 0, validPreparation, 1))
    }

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
    fun encryptedBaselineReadFailureIsPreservedAndNotTreatedAsEmpty() {
        val result = AppPermissionAudit.readBaselinePreference {
            throw IOException("Keystore authentication failed")
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
