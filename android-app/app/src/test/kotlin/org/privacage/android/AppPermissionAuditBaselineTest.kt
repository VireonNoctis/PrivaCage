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
        val invalidVersions = listOf("1.5", "2", "\"1\"", "true", "null")
        for (version in invalidVersions) {
            val json = """{"schema_version":$version,"packages":{}}"""
            assertThrows("schema_version=$version", IOException::class.java) {
                AppPermissionAudit.decodeBaseline(json)
            }
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
