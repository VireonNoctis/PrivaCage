package org.privacage.audit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AsciiMultiPatternMatcherTest {

    @Test
    fun matchesCaseInsensitivelyAcrossBufferBoundaries() {
        val matcher = AsciiMultiPatternMatcher(
            listOf(
                AsciiSearchPattern("full", "google-analytics.com"),
                AsciiSearchPattern("suffix", "analytics.com")
            )
        )

        assertTrue(matcher.feed("https://www.GOOGLE-ANALYTICS".toByteArray()).isEmpty())
        assertEquals(setOf("full", "suffix"), matcher.feed(".COM/g/collect".toByteArray()))
    }

    @Test
    fun returnsOverlappingAndSuffixPatterns() {
        val matcher = AsciiMultiPatternMatcher(
            listOf(
                AsciiSearchPattern("domain", "example.com"),
                AsciiSearchPattern("subdomain", "tracker.example.com")
            )
        )

        assertEquals(
            setOf("domain", "subdomain"),
            matcher.feed("tracker.example.com".toByteArray())
        )
    }

    @Test
    fun canBeResetBetweenIndependentStreams() {
        val matcher = AsciiMultiPatternMatcher(listOf(AsciiSearchPattern("hit", "indicator.example")))
        assertTrue(matcher.feed("indicator.ex".toByteArray()).isEmpty())
        matcher.reset()
        assertTrue(matcher.feed("ample".toByteArray()).isEmpty())
        assertEquals(setOf("hit"), matcher.feed("indicator.example".toByteArray()))
    }

    @Test
    fun supportsOffsetsAndZeroLengthChunks() {
        val matcher = AsciiMultiPatternMatcher(listOf(AsciiSearchPattern("hit", "clarity.ms")))
        val bytes = "prefix clarity.ms suffix".toByteArray()
        assertTrue(matcher.feed(bytes, offset = 0, length = 0).isEmpty())
        assertEquals(setOf("hit"), matcher.feed(bytes, offset = 7, length = 10))
    }

    @Test
    fun rejectsEmptyAndNonAsciiPatterns() {
        assertFailsWith<IllegalArgumentException> {
            AsciiMultiPatternMatcher(listOf(AsciiSearchPattern("empty", "")))
        }
        assertFailsWith<IllegalArgumentException> {
            AsciiMultiPatternMatcher(listOf(AsciiSearchPattern("unicode", "münchen.example")))
        }
    }
}
