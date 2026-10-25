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
