package org.privacage.rights

import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PrivacyRightsRequestBuilderTest {
    private val preparedOn = LocalDate.parse("2026-10-27")

    @Test
    fun ukGdprUsesCalendarMonthRatherThanFixedThirtyDays() {
        val draft = PrivacyRightsRequestBuilder.createDraft(
            jurisdiction = RightsJurisdiction.UK_GDPR,
            right = PrivacyRight.ERASURE,
            controllerName = "Example Controller",
            preparedOn = LocalDate.parse("2026-02-28"),
            receivedOn = LocalDate.parse("2026-01-31")
        )

        assertEquals(LocalDate.parse("2026-02-28"), draft.standardResponseDueOn)
        assertNull(draft.extendedResponseDueOn)
        assertTrue(draft.message.contains("UK data protection law"))
        assertTrue(draft.message.contains("I have not attached identity documents"))
        assertTrue(draft.officialGuidanceUrl.startsWith("https://ico.org.uk/"))
    }

    @Test
    fun californiaCcpaDeadlineAndExtensionRequireReceiptAndNotice() {
        val received = LocalDate.parse("2026-10-01")
        val normal = PrivacyRightsRequestBuilder.createDraft(
            jurisdiction = RightsJurisdiction.CALIFORNIA_CCPA,
            right = PrivacyRight.ACCESS,
            controllerName = "Example Business",
            preparedOn = preparedOn,
            receivedOn = received
        )
        val extended = PrivacyRightsRequestBuilder.createDraft(
            jurisdiction = RightsJurisdiction.CALIFORNIA_CCPA,
            right = PrivacyRight.ACCESS,
            controllerName = "Example Business",
            preparedOn = preparedOn,
            receivedOn = received,
            extensionNoticeRecorded = true
        )

        assertEquals(LocalDate.parse("2026-10-15"), normal.acknowledgementReminderOn)
        assertEquals(LocalDate.parse("2026-11-14"), normal.standardResponseDueOn)
        assertNull(normal.extendedResponseDueOn)
        assertEquals(LocalDate.parse("2026-10-15"), extended.acknowledgementReminderOn)
        assertEquals(LocalDate.parse("2026-12-29"), extended.extendedResponseDueOn)
        assertTrue(normal.responsePeriodNote.contains("10-business-day"))
        assertTrue(normal.responsePeriodNote.contains("45-calendar-day"))
        assertTrue(normal.responsePeriodNote.contains("receipt date as day one"))
    }

    @Test
    fun californiaOptOutUsesFifteenBusinessDaysAndNoFortyFiveDayExtension() {
        val draft = PrivacyRightsRequestBuilder.createDraft(
            jurisdiction = RightsJurisdiction.CALIFORNIA_CCPA,
            right = PrivacyRight.OPT_OUT,
            controllerName = "Example Business",
            preparedOn = LocalDate.parse("2026-11-28"),
            receivedOn = LocalDate.parse("2026-10-30"),
            extensionNoticeRecorded = true
        )

        assertNull(draft.acknowledgementReminderOn)
        assertEquals(LocalDate.parse("2026-11-20"), draft.standardResponseDueOn)
        assertNull(draft.extendedResponseDueOn)
        assertTrue(draft.responsePeriodNote.contains("15 business days"))
        assertTrue(draft.responsePeriodNote.contains("does not account for California state holidays"))
        assertTrue(draft.responsePeriodNote.contains("does not extend this date"))
    }

    @Test
    fun californiaRightToLimitUsesDistinctFifteenBusinessDayPath() {
        val draft = PrivacyRightsRequestBuilder.createDraft(
            jurisdiction = RightsJurisdiction.CALIFORNIA_CCPA,
            right = PrivacyRight.LIMIT_SENSITIVE,
            controllerName = "Example Business",
            preparedOn = preparedOn,
            receivedOn = LocalDate.parse("2026-10-30"),
            extensionNoticeRecorded = true
        )

        assertEquals("LIMIT_SENSITIVE", draft.right.name)
        assertNull(draft.acknowledgementReminderOn)
        assertEquals(LocalDate.parse("2026-11-20"), draft.standardResponseDueOn)
        assertNull(draft.extendedResponseDueOn)
        assertTrue(draft.message.contains("limit the use and disclosure"))
        assertTrue(draft.message.contains("verifiable consumer request is not required"))
        assertTrue(draft.responsePeriodNote.contains("sensitive personal information"))
        assertTrue(draft.responsePeriodNote.contains("15 business days"))
        assertTrue(draft.responsePeriodNote.contains("does not account for California state holidays"))
    }

    @Test
    fun rejectsRightToLimitOutsideCaliforniaCcpa() {
        assertFailsWith<IllegalArgumentException> {
            PrivacyRightsRequestBuilder.createDraft(
                jurisdiction = RightsJurisdiction.UK_GDPR,
                right = PrivacyRight.LIMIT_SENSITIVE,
                controllerName = "Example Controller",
                preparedOn = preparedOn
            )
        }
    }

    @Test
    fun californiaAcknowledgementReminderCountsTenWeekdaysAfterReceipt() {
        val draft = PrivacyRightsRequestBuilder.createDraft(
            jurisdiction = RightsJurisdiction.CALIFORNIA_CCPA,
            right = PrivacyRight.CORRECTION,
            controllerName = "Example Business",
            preparedOn = preparedOn,
            receivedOn = LocalDate.parse("2026-11-27")
        )

        assertEquals(LocalDate.parse("2026-12-11"), draft.acknowledgementReminderOn)
    }

    @Test
    fun dropDoesNotSupportAnIndividualControllerReceiptDate() {
        assertFalse(PrivacyRightsRequestBuilder.supportsIndividualReceiptDate(RightsJurisdiction.CALIFORNIA_DROP))
        assertTrue(PrivacyRightsRequestBuilder.supportsIndividualReceiptDate(RightsJurisdiction.CALIFORNIA_CCPA))
        assertTrue(PrivacyRightsRequestBuilder.supportsIndividualReceiptDate(RightsJurisdiction.UK_GDPR))
    }

    @Test
    fun preparationDoesNotPretendToBeSubmissionOrReceipt() {
        val draft = PrivacyRightsRequestBuilder.createDraft(
            jurisdiction = RightsJurisdiction.CALIFORNIA_CCPA,
            right = PrivacyRight.ERASURE,
            controllerName = "Example Business",
            preparedOn = preparedOn
        )

        assertNull(draft.receivedOn)
        assertNull(draft.standardResponseDueOn)
        assertFalse(draft.message.contains("has received my request"))
    }

    @Test
    fun dropDraftIsGuidanceOnlyAndHasNoClaimedConsumerDeadline() {
        val draft = PrivacyRightsRequestBuilder.createDraft(
            jurisdiction = RightsJurisdiction.CALIFORNIA_DROP,
            right = PrivacyRight.ERASURE,
            preparedOn = preparedOn
        )

        assertNull(draft.controllerName)
        assertNull(draft.standardResponseDueOn)
        assertNull(draft.extendedResponseDueOn)
        assertNull(draft.acknowledgementReminderOn)
        assertTrue(draft.message.contains("PrivaCage does not collect or submit it"))
        assertTrue(draft.message.contains("California residency eligibility"))
        assertTrue(draft.message.contains("Keep your DROP ID private"))
        assertTrue(draft.message.contains("Do not paste it into PrivaCage"))
        assertEquals("https://privacy.ca.gov/drop/", draft.officialGuidanceUrl)
        assertTrue(draft.responsePeriodNote.contains("newly matching data at least every 45 days"))
        assertTrue(draft.responsePeriodNote.contains("up to 90 days"))
        assertTrue(draft.responsePeriodNote.contains("not an individual response deadline"))
    }

    @Test
    fun requiresControllerForDirectRequestAndBoundsScope() {
        assertFailsWith<IllegalArgumentException> {
            PrivacyRightsRequestBuilder.createDraft(
                jurisdiction = RightsJurisdiction.UK_GDPR,
                right = PrivacyRight.ACCESS,
                preparedOn = preparedOn
            )
        }
        assertFailsWith<IllegalArgumentException> {
            PrivacyRightsRequestBuilder.createDraft(
                jurisdiction = RightsJurisdiction.UK_GDPR,
                right = PrivacyRight.ACCESS,
                controllerName = "Example",
                scopeDescription = "x".repeat(8_001),
                preparedOn = preparedOn
            )
        }
        assertFailsWith<IllegalArgumentException> {
            PrivacyRightsRequestBuilder.createDraft(
                jurisdiction = RightsJurisdiction.CALIFORNIA_CCPA,
                right = PrivacyRight.ACCESS,
                controllerName = "Example",
                preparedOn = preparedOn,
                receivedOn = LocalDate.now().plusDays(1)
            )
        }
    }

    @Test
    fun lifecycleRequiresExplicitSubmissionAndDoesNotClaimVerifiedDeletion() {
        assertTrue(PrivacyRightsRequestBuilder.canTransition(RightsRequestStatus.DRAFT, RightsRequestStatus.REVIEWED))
        assertTrue(PrivacyRightsRequestBuilder.canTransition(RightsRequestStatus.REVIEWED, RightsRequestStatus.SUBMITTED))
        assertTrue(PrivacyRightsRequestBuilder.canTransition(RightsRequestStatus.SUBMITTED, RightsRequestStatus.ACKNOWLEDGED))
        assertTrue(PrivacyRightsRequestBuilder.canTransition(RightsRequestStatus.ACKNOWLEDGED, RightsRequestStatus.RESPONSE_RECEIVED))
        assertTrue(PrivacyRightsRequestBuilder.canTransition(RightsRequestStatus.RESPONSE_RECEIVED, RightsRequestStatus.OUTCOME_REPORTED))
        assertFalse(PrivacyRightsRequestBuilder.canTransition(RightsRequestStatus.DRAFT, RightsRequestStatus.SUBMITTED))
        assertFalse(PrivacyRightsRequestBuilder.canTransition(RightsRequestStatus.OUTCOME_REPORTED, RightsRequestStatus.SUBMITTED))
    }
}
