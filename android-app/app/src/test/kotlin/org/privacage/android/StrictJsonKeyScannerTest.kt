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
        assertTrue(exception.message.orEmpty().contains("duplicate"))
        assertTrue(!exception.message.orEmpty().contains("format"), "Diagnostics must not echo hostile key names")
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
    fun acceptsValidEscapedSurrogatePairs() {
        StrictJsonKeyScanner.validate("""{"value":"\uD83D\uDE00"}""", "test JSON")
    }

    @Test
    fun rejectsUnpairedEscapedHighAndLowSurrogates() {
        assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate("""{"value":"\uD800"}""", "test JSON")
        }
        assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate("""{"value":"\uDC00"}""", "test JSON")
        }
        assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate("""{"value":"\uD800\u0041"}""", "test JSON")
        }
    }

    @Test
    fun acceptsValidLiteralSurrogatePairs() {
        val pair = charArrayOf(0xD83D.toChar(), 0xDE00.toChar()).concatToString()
        StrictJsonKeyScanner.validate("""{"value":"${pair}"}""", "test JSON")
    }

    @Test
    fun rejectsLiteralUnpairedSurrogates() {
        val high = 0xD800.toChar()
        val low = 0xDC00.toChar()
        assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate("""{"value":"${high}"}""", "test JSON")
        }
        assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate("""{"value":"${low}"}""", "test JSON")
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

    @Test
    fun duplicateKeyDiagnosticsDoNotEchoAttackerControlledNames() {
        val hostileKey = "x".repeat(64 * 1024)
        val json = "{\"" + hostileKey + "\":1,\"" + hostileKey + "\":2}"
        val exception = assertThrows(IOException::class.java) {
            StrictJsonKeyScanner.validate(json, "test JSON")
        }
        assertTrue(exception.message.orEmpty().length < 256)
        assertTrue(!exception.message.orEmpty().contains(hostileKey))
    }
}
