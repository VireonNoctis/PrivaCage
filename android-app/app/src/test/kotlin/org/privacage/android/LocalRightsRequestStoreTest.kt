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
        receivedOn: String? = null,
        standardDueOn: String? = null,
        extendedDueOn: String? = null,
        extensionNoticeRecorded: Boolean = false,
        extra: String = ""
    ): String = """{"id":"$id","jurisdiction":"$jurisdiction","right":"ERASURE","controller_name":$controller,"prepared_on":"2026-10-27","received_on":${receivedOn?.let { "\"$it\"" } ?: "null"},"standard_due_on":${standardDueOn?.let { "\"$it\"" } ?: "null"},"extended_due_on":${extendedDueOn?.let { "\"$it\"" } ?: "null"},"extension_notice_recorded":$extensionNoticeRecorded,"status":"DRAFT","official_guidance_url":"$guidanceUrl"$extra}"""

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
    fun readsLegacyRecordsWithOmittedNullableFields() {
        val legacy = record()
            .replace(",\"received_on\":null", "")
            .replace(",\"standard_due_on\":null", "")
            .replace(",\"extended_due_on\":null", "")

        val decoded = LocalRightsRequestStore.decodeRecords("[$legacy]").single()

        assertEquals(null, decoded.receivedOn)
        assertEquals(null, decoded.standardResponseDueOn)
        assertEquals(null, decoded.extendedResponseDueOn)
        assertEquals("Example Controller", decoded.controllerName)
        // Re-encoding upgrades old omitted-null fields to the canonical explicit-null form.
        val roundTrip = LocalRightsRequestStore.decodeRecords(
            LocalRightsRequestStore.encodeRecords(listOf(decoded))
        ).single()
        assertEquals(decoded, roundTrip)
    }

    @Test
    fun acceptsDropChecklistWithoutControllerOrIndividualDeadline() {
        val dropRecord = record(
            jurisdiction = "CALIFORNIA_DROP",
            controller = "null",
            guidanceUrl = "https://privacy.ca.gov/drop/"
        )

        val decoded = LocalRightsRequestStore.decodeRecords("[$dropRecord]").single()

        assertEquals(null, decoded.controllerName)
        assertEquals(null, decoded.standardResponseDueOn)
        assertEquals(null, decoded.extendedResponseDueOn)

        val legacyDropRecord = dropRecord
            .replace("\"controller_name\":null,", "")
            .replace(",\"received_on\":null", "")
            .replace(",\"standard_due_on\":null", "")
            .replace(",\"extended_due_on\":null", "")
        val legacyDrop = LocalRightsRequestStore.decodeRecords("[$legacyDropRecord]").single()
        assertEquals(null, legacyDrop.controllerName)
        assertEquals(null, legacyDrop.receivedOn)
        assertEquals(null, legacyDrop.standardResponseDueOn)
        assertEquals(null, legacyDrop.extendedResponseDueOn)

        val roundTrip = LocalRightsRequestStore.decodeRecords(
            LocalRightsRequestStore.encodeRecords(listOf(decoded))
        ).single()
        assertEquals(decoded, roundTrip)
    }

    @Test
    fun migratesLegacyBrokerFacingDropUrlToTheConsumerEntryPoint() {
        val legacy = record(
            jurisdiction = "CALIFORNIA_DROP",
            controller = "null",
            guidanceUrl = "https://cppa.ca.gov/data_brokers/"
        )

        val decoded = LocalRightsRequestStore.decodeRecords("[$legacy]").single()

        assertEquals("https://privacy.ca.gov/drop/", decoded.officialGuidanceUrl)
        assertEquals(decoded, LocalRightsRequestStore.decodeRecords(
            LocalRightsRequestStore.encodeRecords(listOf(decoded))
        ).single())
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
    fun validatesJurisdictionSpecificPlanningDates() {
        val uk = LocalRightsRequestStore.decodeRecords(
            "[${record(
                receivedOn = "2026-10-27",
                standardDueOn = "2026-11-27",
                extendedDueOn = "2027-01-27",
                extensionNoticeRecorded = true
            )}]"
        ).single()
        assertEquals("2026-11-27", uk.standardResponseDueOn.toString())
        assertEquals("2027-01-27", uk.extendedResponseDueOn.toString())

        val california = LocalRightsRequestStore.decodeRecords(
            "[${record(
                jurisdiction = "CALIFORNIA_CCPA",
                guidanceUrl = "https://cppa.ca.gov/faq/",
                receivedOn = "2026-10-27",
                standardDueOn = "2026-12-11",
                extendedDueOn = "2027-01-25",
                extensionNoticeRecorded = true
            )}]"
        ).single()
        assertEquals("2026-12-11", california.standardResponseDueOn.toString())
        assertEquals("2027-01-25", california.extendedResponseDueOn.toString())
    }

    @Test
    fun rejectsPlanningDatesThatDoNotMatchTheConfiguredCalculation() {
        val incorrectStandard = record(
            receivedOn = "2026-10-27",
            standardDueOn = "2026-11-26"
        )
        val incorrectExtension = record(
            receivedOn = "2026-10-27",
            standardDueOn = "2026-11-27",
            extendedDueOn = "2027-01-26",
            extensionNoticeRecorded = true
        )
        val incorrectCalifornia = record(
            jurisdiction = "CALIFORNIA_CCPA",
            guidanceUrl = "https://cppa.ca.gov/faq/",
            receivedOn = "2026-10-27",
            standardDueOn = "2026-12-10"
        )

        listOf(incorrectStandard, incorrectExtension, incorrectCalifornia).forEach { raw ->
            assertThrows(IllegalStateException::class.java) {
                LocalRightsRequestStore.decodeRecords("[$raw]")
            }
        }
    }

    @Test
    fun validatesWritesBeforeReturningPersistableJson() {
        val valid = LocalRightsRequestStore.decodeRecords("[${record()}]").single()
        val encoded = LocalRightsRequestStore.encodeRecords(listOf(valid))
        assertEquals(listOf(valid), LocalRightsRequestStore.decodeRecords(encoded))

        assertThrows(IllegalArgumentException::class.java) {
            LocalRightsRequestStore.encodeRecords(listOf(valid.copy(controllerName = " Example Controller ")))
        }
        assertThrows(IllegalArgumentException::class.java) {
            LocalRightsRequestStore.encodeRecords(listOf(valid.copy(controllerName = "x".repeat(257))))
        }
        assertThrows(IllegalArgumentException::class.java) {
            LocalRightsRequestStore.encodeRecords(listOf(valid, valid))
        }
        assertThrows(IllegalArgumentException::class.java) {
            LocalRightsRequestStore.encodeRecords((0..100).map { index ->
                valid.copy(id = UUID(1L, index.toLong()).toString())
            })
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
