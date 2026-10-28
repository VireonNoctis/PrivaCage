package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class AppAlternativeCatalogTest {
    @Test
    fun parsesTrustedCatalogEntryAndSource() {
        val entries = AppAlternativeCatalog.parseJson(document())
        assertEquals(1, entries.size)
        assertEquals("ch.protonmail.android", entries.single().packageName)
        assertEquals("Gmail", entries.single().replaces)
        assertEquals("Proton Mail", entries.single().name)
        assertEquals("play", entries.single().sources.single().id)
        assertEquals("play.google.com", entries.single().sources.single().url.substringAfter("https://").substringBefore('/'))
    }

    @Test
    fun rejectsUnpinnedSchemaFields() {
        val invalid = document().replace(
            "\"schema_version\": 1",
            "\"schema_version\": 2"
        )
        assertFails(invalid, "schema version")
    }

    @Test
    fun rejectsDecimalOrStringSchemaVersions() {
        assertFails(document().replace("\"schema_version\": 1", "\"schema_version\": 1.0"), "exact integer")
        assertFails(document().replace("\"schema_version\": 1", "\"schema_version\": \"1\""), "exact integer")
    }

    @Test
    fun rejectsNonCanonicalCalendarDates() {
        assertFails(document().replace("2026-10-25", "2026-1-25"), "canonical YYYY-MM-DD")
    }

    @Test
    fun rejectsInvalidExpectedPackageNames() {
        assertFails(document().replace("ch.protonmail.android", "ch/protonmail/android"), "valid dotted Android package name")
    }

    @Test
    fun rejectsInsecureHttpUrls() {
        assertFails(document().replace("https://play.google.com", "http://play.google.com"), "HTTPS")
    }

    @Test
    fun rejectsUnapprovedHosts() {
        assertFails(document().replace("https://play.google.com", "https://play.google.com.attacker.invalid"), "reviewed host")
    }

    @Test
    fun rejectsDuplicateAlternativeIds() {
        val duplicate = document().replace(
            "\"alternatives\": [",
            "\"alternatives\": [${entry()},"
        )
        assertFails(duplicate, "Duplicate alternative id")
    }

    @Test
    fun rejectsDuplicateSourceIdsWithinAnAlternative() {
        val invalid = document().replace(
            "\"sources\": [${source()}]",
            "\"sources\": [${source()},${source()}]"
        )
        assertFails(invalid, "Duplicate source type")
    }


    @Test
    fun rejectsDuplicateAndEscapedEquivalentObjectKeysBeforeJsonCoercion() {
        assertFails(
            document().replace("\"schema_version\": 1,", "\"schema_version\": 1, \"schema_version\": 1,"),
            "ambiguous JSON"
        )
        assertFails(
            document().replace("\"schema_version\": 1,", "\"schema_version\": 1, \"schema\\u005fversion\": 1,"),
            "ambiguous JSON"
        )
    }

    @Test
    fun rejectsEveryTruncatedCataloguePrefix() {
        val source = document()
        for (length in 0 until source.length) {
            assertFails(source.substring(0, length), "ambiguous JSON")
        }
    }

    @Test
    fun enforcesCatalogueByteLimitAtAndBeyondTheBoundary() {
        val source = document()
        val limit = 512 * 1024
        val exact = source + " ".repeat(limit - source.toByteArray(Charsets.UTF_8).size)
        assertEquals(1, AppAlternativeCatalog.parseJson(exact).size)
        assertFails(exact + " ", "size limit")
    }

    @Test
    fun oversizedUnknownFieldDoesNotLeakIntoDiagnostic() {
        val hostileField = "x".repeat(100_000)
        val source = document().dropLast(1) + ",\"" + hostileField + "\":null}"
        try {
            AppAlternativeCatalog.parseJson(source)
            throw AssertionError("Expected an unknown field to be rejected")
        } catch (exception: IOException) {
            assertTrue(exception.message.orEmpty().length < 256)
            assertTrue(!exception.message.orEmpty().contains(hostileField))
        }
    }


    @Test
    fun seededCatalogueMutationsNeverLeakUnexpectedRuntimeExceptions() {
        val source = document()
        val random = java.util.Random(0x414c5443L)
        repeat(256) { caseIndex ->
            val mutated = source.toCharArray()
            val index = random.nextInt(mutated.size)
            mutated[index] = (mutated[index].code xor (1 shl random.nextInt(7))).toChar()
            val result = runCatching { AppAlternativeCatalog.parseJson(mutated.concatToString()) }
            val failure = result.exceptionOrNull()
            assertTrue(
                result.isSuccess || failure is IOException,
                "Mutation $caseIndex escaped the catalogue error contract: $failure"
            )
        }
    }

    private fun assertFails(value: String, messagePart: String) {
        try {
            AppAlternativeCatalog.parseJson(value)
            throw AssertionError("Expected catalogue validation to fail")
        } catch (exception: IOException) {
            assertTrue("Expected error to contain '" + messagePart + "' but got: " + exception.message,
                exception.message?.contains(messagePart, ignoreCase = true) == true)
        }
    }

    private fun document(): String = """{
      "schema_version": 1,
      "updated_at": "2026-10-25",
      "alternatives": [${entry()}]
    }"""

    private fun entry(): String = """{
      "id": "gmail-proton-mail",
      "package_name": "ch.protonmail.android",
      "replaces": "Gmail",
      "category": "Email",
      "name": "Proton Mail",
      "summary": "Privacy-oriented email.",
      "tradeoffs": "Account and mail-delivery metadata still exist.",
      "evidence_url": "https://proton.me/mail/security",
      "sources": [${source()}]
    }"""

    private fun source(): String = """{
      "id": "play",
      "label": "Google Play",
      "url": "https://play.google.com/store/apps/details?id=ch.protonmail.android"
    }"""
}
