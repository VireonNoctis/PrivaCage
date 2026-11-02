package org.privacage.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class LocalRightsRequestStoreTest {
    private val validId = "5f7e3e62-4d3a-4c4f-a82d-3f1b8c8e7f10"

    private fun record(
        id: String = validId,
        jurisdiction: String = "UK_GDPR",
        controller: String = "\"Example Controller\"",
        guidanceUrl: String = "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/",
        extra: String = ""
    ): String = """{"id":"$id","jurisdiction":"$jurisdiction","right":"ERASURE","controller_name":$controller,"prepared_on":"2026-10-27","received_on":null,"standard_due_on":null,"extended_due_on":null,"extension_notice_recorded":false,"status":"DRAFT","official_guidance_url":"$guidanceUrl"$extra}"""

    @Test
    fun readsCanonicalLocalDraftMetadata() {
        val decoded = LocalRightsRequestStore.decodeRecords("[${record()}]").single()

        assertEquals(validId, decoded.id)
        assertEquals("Example Controller", decoded.controllerName)
        assertEquals("https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/", decoded.officialGuidanceUrl)
        assertEquals(false, decoded.extensionNoticeRecorded)
        assertTrue(decoded.displayLabel().contains("Example Controller"))
    }

    @Test
    fun acceptsDropChecklistWithoutControllerOrIndividualDeadline() {
        val dropRecord = record(
            jurisdiction = "CALIFORNIA_DROP",
            controller = "null",
            guidanceUrl = "https://cppa.ca.gov/data_brokers/"
        )

        val decoded = LocalRightsRequestStore.decodeRecords("[$dropRecord]").single()

        assertEquals(null, decoded.controllerName)
        assertEquals(null, decoded.standardResponseDueOn)
        assertEquals(null, decoded.extendedResponseDueOn)
    }

    @Test
    fun rejectsMalformedAndNonCanonicalRecordIds() {
        listOf("not-a-uuid", validId.uppercase()).forEach { id ->
            assertThrows(IllegalStateException::class.java) {
                LocalRightsRequestStore.decodeRecords("[${record(id = id)}]")
            }
        }
    }

    @Test
    fun rejectsControllerControlCharactersAndUntrimmedValues() {
        val controlCharacter = record(controller = "\"Example\\nController\"")
        val padded = record(controller = "\" Example Controller \"")

        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords("[$controlCharacter]")
        }
        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords("[$padded]")
        }
    }

    @Test
    fun rejectsGuidanceUrlsThatDoNotExactlyMatchTheirJurisdiction() {
        val mismatched = record(guidanceUrl = "https://ico.org.uk.evil.example/")

        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords("[$mismatched]")
        }
    }

    @Test
    fun rejectsMissingFieldsAndNonBooleanExtensionFlags() {
        val missingField = record().replace(",\"status\":\"DRAFT\"", "")
        val wrongType = record().replace("\"extension_notice_recorded\":false", "\"extension_notice_recorded\":\"false\"")

        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords("[$missingField]")
        }
        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords("[$wrongType]")
        }
    }

    @Test
    fun rejectsDeadlinesWithoutReceiptAndDropDeadlines() {
        val noReceiptDeadline = record().replace("\"standard_due_on\":null", "\"standard_due_on\":\"2026-11-27\"")
        val dropDeadline = record(
            jurisdiction = "CALIFORNIA_DROP",
            controller = "null",
            guidanceUrl = "https://cppa.ca.gov/data_brokers/"
        ).replace("\"standard_due_on\":null", "\"standard_due_on\":\"2026-11-27\"")

        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords("[$noReceiptDeadline]")
        }
        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords("[$dropDeadline]")
        }
    }

    @Test
    fun rejectsDuplicateRecordIdsAndOversizedOrOverCountStores() {
        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords("[${record()},${record()}]")
        }

        val tooManyRecords = (0..100).joinToString(prefix = "[", postfix = "]") { index ->
            record(id = UUID(0L, index.toLong()).toString())
        }
        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords(tooManyRecords)
        }

        assertThrows(IllegalStateException::class.java) {
            LocalRightsRequestStore.decodeRecords(" ".repeat(512 * 1024 + 1))
        }
    }

    @Test
    fun emptyStoreRemainsAValidEmptyList() {
        assertTrue(LocalRightsRequestStore.decodeRecords("[]").isEmpty())
        assertFalse(LocalRightsRequestStore.decodeRecords("[]").any())
    }
}
