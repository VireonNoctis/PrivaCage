package org.privacage.android

import java.io.IOException
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class StrictJsonKeyScannerTest {
    @Test
    fun acceptsNestedJsonAndEscapedStringValues() {
        StrictJsonKeyScanner.validate(
            """{"schema_version":1,"items":[{"name":"quoted \"text\"","enabled":true,"weight":-1.25e+2}]}""",
            "test JSON"
        )
    }

    @Test
    fun rejectsDuplicateKeysAtTheSameObjectLevel() {
        val exception = assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate("""{"enabled":true,"enabled":false}""", "test JSON")
        }
        assertTrue(exception.message.orEmpty().contains("duplicate"))
    }

    @Test
    fun rejectsDuplicateKeysAfterUnicodeEscapeDecoding() {
        val json = "{\"format\":1,\"fo\\u0072mat\":2}"
        val exception = assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate(json, "test JSON")
        }
        assertTrue(exception.message.orEmpty().contains("format"))
    }

    @Test
    fun rejectsDuplicateKeysInNestedObjects() {
        assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate(
                """{"outer":{"permission":true,"permission":false}}""",
                "test JSON"
            )
        }
    }

    @Test
    fun rejectsMalformedPrimitivesTrailingValuesAndOverdeepNesting() {
        assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate("""{"value":01}""", "test JSON")
        }
        assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate("""{} {}""", "test JSON")
        }
        val tooDeep = "[".repeat(66) + "0" + "]".repeat(66)
        assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate(tooDeep, "test JSON")
        }
    }
}
