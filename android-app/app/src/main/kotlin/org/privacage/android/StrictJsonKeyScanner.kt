package org.privacage.android

import java.io.IOException

internal object StrictJsonKeyScanner {
    private const val MAX_NESTING = 64
    private const val MAX_JSON_CHARACTERS = 5 * 1024 * 1024
    private val JSON_NUMBER = Regex("""-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?""")

    @Throws(IOException::class)
    fun validate(source: String, label: String) {
        if (source.length > MAX_JSON_CHARACTERS) {
            throw IOException("$label exceeds the strict JSON character limit.")
        }
        try {
            Scanner(source).scan()
        } catch (exception: IOException) {
            throw IOException("$label is malformed or contains duplicate JSON object keys: ${exception.message}", exception)
        }
    }

    private class Scanner(private val source: String) {
            private var cursor = 0
    
            fun scan() {
                skipWhitespace()
                parseValue(0)
                skipWhitespace()
                if (cursor != source.length) malformed()
            }
    
            private fun parseValue(depth: Int) {
                if (depth > MAX_NESTING) throw IOException("JSON nesting exceeds the supported limit.")
                skipWhitespace()
                if (cursor >= source.length) malformed()
                when (source[cursor]) {
                    '{' -> parseObject(depth)
                    '[' -> parseArray(depth)
                    '"' -> parseString()
                    else -> parsePrimitive()
                }
            }
    
            private fun parseObject(depth: Int) {
                cursor += 1 // {
                skipWhitespace()
                if (take('}')) return
                val keys = HashSet<String>()
                while (true) {
                    skipWhitespace()
                    if (cursor >= source.length || source[cursor] != '"') malformed()
                    val key = parseString()
                    if (!keys.add(key)) throw IOException("Duplicate JSON object key '$key'.")
                    skipWhitespace()
                    expect(':')
                    parseValue(depth + 1)
                    skipWhitespace()
                    if (take(',')) continue
                    if (take('}')) return
                    malformed()
                }
            }
    
            private fun parseArray(depth: Int) {
                cursor += 1 // [
                skipWhitespace()
                if (take(']')) return
                while (true) {
                    parseValue(depth + 1)
                    skipWhitespace()
                    if (take(',')) continue
                    if (take(']')) return
                    malformed()
                }
            }
    
            private fun parseString(): String {
                expect('"')
                val decoded = StringBuilder()
                while (cursor < source.length) {
                    val character = source[cursor++]
                    when {
                        character == '"' -> return decoded.toString()
                        character == '\\' -> {
                            if (cursor >= source.length) malformed()
                            when (val escaped = source[cursor++]) {
                                '"', '\\', '/' -> decoded.append(escaped)
                                'b' -> decoded.append('\b')
                                'f' -> decoded.append('\u000c')
                                'n' -> decoded.append('\n')
                                'r' -> decoded.append('\r')
                                't' -> decoded.append('\t')
                                'u' -> {
                                    if (cursor + 4 > source.length) malformed()
                                    val hex = source.substring(cursor, cursor + 4)
                                    if (hex.any { it.digitToIntOrNull(16) == null }) malformed()
                                    val codeUnit = hex.toInt(16)
                                    cursor += 4
                                    when (codeUnit) {
                                        in 0xD800..0xDBFF -> {
                                            if (
                                                cursor + 6 > source.length ||
                                                source[cursor] != '\\' ||
                                                source[cursor + 1] != 'u'
                                            ) malformed()
                                            val lowHex = source.substring(cursor + 2, cursor + 6)
                                            if (lowHex.any { it.digitToIntOrNull(16) == null }) malformed()
                                            val lowUnit = lowHex.toInt(16)
                                            if (lowUnit !in 0xDC00..0xDFFF) malformed()
                                            decoded.append(codeUnit.toChar()).append(lowUnit.toChar())
                                            cursor += 6
                                        }
                                        in 0xDC00..0xDFFF -> malformed()
                                        else -> decoded.append(codeUnit.toChar())
                                    }
                                }
                                else -> malformed()
                            }
                        }
                        character.code < 0x20 -> malformed()
                        else -> decoded.append(character)
                    }
                }
                malformed()
            }
    
            private fun parsePrimitive() {
                val start = cursor
                while (cursor < source.length) {
                    val character = source[cursor]
                    if (
                        character == ',' || character == ']' || character == '}' ||
                        character == ' ' || character == '\n' ||
                        character == '\r' || character == '\t'
                    ) {
                        break
                    }
                    cursor += 1
                }
                if (cursor == start) malformed()
                val token = source.substring(start, cursor)
                if (token != "true" && token != "false" && token != "null" &&
                    !JSON_NUMBER.matches(token)
                ) {
                    malformed()
                }
            }
    
            private fun skipWhitespace() {
                while (cursor < source.length) {
                    when (source[cursor]) {
                        ' ', '\n', '\r', '\t' -> cursor += 1
                        else -> return
                    }
                }
            }
            private fun expect(expected: Char) {
                if (!take(expected)) malformed()
            }
    
            private fun take(expected: Char): Boolean {
                if (cursor < source.length && source[cursor] == expected) {
                    cursor += 1
                    return true
                }
                return false
            }
    
            private fun malformed(): Nothing = throw IOException("Malformed JSON.")
        }
}
