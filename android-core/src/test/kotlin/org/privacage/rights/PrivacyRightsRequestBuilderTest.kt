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

        assertEquals(LocalDate.parse("2026-11-15"), normal.standardResponseDueOn)
        assertNull(normal.extendedResponseDueOn)
        assertEquals(LocalDate.parse("2026-12-30"), extended.extendedResponseDueOn)
        assertTrue(normal.responsePeriodNote.contains("45-calendar-day"))
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
        assertTrue(draft.message.contains("PrivaCage does not submit this request"))
        assertTrue(draft.officialGuidanceUrl.startsWith("https://cppa.ca.gov/"))
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
