package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class AppPermissionAuditBaselineTest {
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
