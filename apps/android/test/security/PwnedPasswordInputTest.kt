package org.privacage.security

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PwnedPasswordInputTest {
    @Test
    fun copiesExactCharactersWithoutTrimmingAndClearsTheEditor() {
        val source = StringBuilder("  leading and trailing spaces 😀  ")
        val copy = PwnedPasswordInput.takeAndClear(source) { source.setLength(0) }
        assertContentEquals("  leading and trailing spaces 😀  ".toCharArray(), copy)
        assertEquals(0, source.length)
        copy.fill('\u0000')
    }

    @Test
    fun clearsTheEditorWhenCharacterCopyFails() {
        val source = object : CharSequence {
            override val length: Int = 3
            override fun get(index: Int): Char {
                if (index == 2) throw IllegalStateException("test copy failure")
                return if (index == 0) 'a' else 'b'
            }
            override fun subSequence(startIndex: Int, endIndex: Int): CharSequence = ""
        }
        var cleared = false
        assertFailsWith<IllegalStateException> {
            PwnedPasswordInput.takeAndClear(source) { cleared = true }
        }
        assertTrue(cleared)
    }
}
