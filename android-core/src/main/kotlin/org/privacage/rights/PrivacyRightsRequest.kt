package org.privacage.rights

import java.time.LocalDate

enum class RightsJurisdiction(
    val label: String,
    val officialGuidanceUrl: String
) {
    UK_GDPR(
        "UK GDPR",
        "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/"
    ),
    CALIFORNIA_CCPA(
        "California CCPA/CPRA",
        "https://cppa.ca.gov/faq/"
    ),
    CALIFORNIA_DROP(
        "California DROP data-broker request",
        "https://cppa.ca.gov/data_brokers/"
    )
}

enum class PrivacyRight(val label: String, val requestPhrase: String) {
    ACCESS("Access my data", "request access to the personal information you process about me"),
    ERASURE("Delete my data", "request erasure or deletion of personal information about me"),
    CORRECTION("Correct my data", "request correction of inaccurate personal information about me"),
    OPT_OUT("Opt out of sale or sharing", "request to opt out of the sale or sharing of my personal information")
}

enum class RightsRequestStatus {
    DRAFT,
    REVIEWED,
    SUBMITTED,
    ACKNOWLEDGED,
    RESPONSE_RECEIVED,
    OUTCOME_REPORTED
}

data class RightsRequestDraft(
    val jurisdiction: RightsJurisdiction,
    val right: PrivacyRight,
    val controllerName: String?,
    val scopeDescription: String,
    val preparedOn: LocalDate,
    val receivedOn: LocalDate?,
    val standardResponseDueOn: LocalDate?,
    val extendedResponseDueOn: LocalDate?,
    val responsePeriodNote: String,
    val officialGuidanceUrl: String,
    val message: String
)

/**
 * Generates a local draft and deadline guidance. It never sends a request, verifies identity,
 * confirms that a controller received a request, or claims the controller deleted data.
 *
 * Current source review: 27 October 2026. Deadline calculations are planning aids; applicable
 * law, eligibility, identity checks, holidays, extensions and regulator guidance must be checked.
 */
object PrivacyRightsRequestBuilder {
    fun createDraft(
        jurisdiction: RightsJurisdiction,
        right: PrivacyRight,
        controllerName: String = "",
        scopeDescription: String = "",
        preparedOn: LocalDate = LocalDate.now(),
        receivedOn: LocalDate? = null,
        extensionNoticeRecorded: Boolean = false
    ): RightsRequestDraft {
        val normalizedController = controllerName.trim().takeIf(String::isNotEmpty)
        val scope = scopeDescription.trim().take(2_000)
        require(scopeDescription.length <= 8_000) { "The request scope is too long." }
        if (jurisdiction != RightsJurisdiction.CALIFORNIA_DROP) {
            require(!normalizedController.isNullOrBlank()) {
                "Enter the controller's name and verify its official privacy contact before sending."
            }
        }
        if (receivedOn != null) {
            require(!receivedOn.isAfter(LocalDate.now())) {
                "The recorded received date cannot be in the future."
            }
        }

        val deadline = when (jurisdiction) {
            RightsJurisdiction.UK_GDPR -> receivedOn?.plusMonths(1)
            RightsJurisdiction.CALIFORNIA_CCPA -> receivedOn?.plusDays(45)
            RightsJurisdiction.CALIFORNIA_DROP -> null
        }
        val extended = if (!extensionNoticeRecorded || receivedOn == null) null else when (jurisdiction) {
            RightsJurisdiction.UK_GDPR -> receivedOn.plusMonths(3)
            RightsJurisdiction.CALIFORNIA_CCPA -> receivedOn.plusDays(90)
            RightsJurisdiction.CALIFORNIA_DROP -> null
        }
        val periodNote = when (jurisdiction) {
            RightsJurisdiction.UK_GDPR ->
                "UK GDPR guidance generally uses one calendar month; a further two months may be permitted for complex or numerous requests with timely notice. Confirm identity-related timing and current ICO guidance. This is not a legal determination."
            RightsJurisdiction.CALIFORNIA_CCPA ->
                "The CPPA states a 45-calendar-day response period for covered requests, with up to another 45 days when necessary and after notice. Its FAQ also describes confirmation within 10 business days for specified request types. Verify eligibility, exceptions and current rules."
            RightsJurisdiction.CALIFORNIA_DROP ->
                "This is a user-guided route through California's official DROP mechanism, not a direct submission by PrivaCage. The CPPA says registered brokers must access the mechanism at least every 45 days beginning 1 August 2026; that is not a guaranteed individual response deadline."
        }
        val message = when (jurisdiction) {
            RightsJurisdiction.UK_GDPR -> buildString {
                append("Subject: Data protection rights request — ").append(right.label).append("\n\n")
                append("To: ").append(normalizedController).append("\n\n")
                append("Hello,\n\nI would like to ").append(right.requestPhrase)
                    .append(" under the UK data protection law applicable to your processing.\n\n")
                if (scope.isNotBlank()) append("Scope / context: ").append(scope).append("\n\n")
                append("Please let me know if you need proportionate, necessary information to verify my identity. ")
                append("I will review any requested identity documents before sharing them. If you cannot fully comply, ")
                append("please explain the decision and any applicable complaint route.\n\n")
                append("I have not attached identity documents to this draft.\n\nRegards,\n[Your name]\n[Contact method]")
            }
            RightsJurisdiction.CALIFORNIA_CCPA -> buildString {
                append("Subject: California privacy request — ").append(right.label).append("\n\n")
                append("To: ").append(normalizedController).append("\n\n")
                append("Hello,\n\nIf this business and my request are within the scope of the CCPA as amended by the CPRA, ")
                append("I would like to ").append(right.requestPhrase).append(".\n\n")
                if (scope.isNotBlank()) append("Scope / context: ").append(scope).append("\n\n")
                append("Please provide the verification steps required for this request and explain any exception or ")
                append("partial denial that you rely on. I will review any request for identity documents before sharing them.\n\n")
                append("I have not attached identity documents to this draft.\n\nRegards,\n[Your name]\n[Contact method]")
            }
            RightsJurisdiction.CALIFORNIA_DROP -> buildString {
                append("CALIFORNIA DROP — USER-GUIDED CHECKLIST\n\n")
                append("1. Open the official CPPA information page and follow its link to the DROP service.\n")
                append("2. Review the official eligibility, identity verification and data-handling notices.\n")
                append("3. Submit directly through the official service; PrivaCage does not submit this request.\n")
                append("4. Save the confirmation/reference yourself only if you choose.\n")
                append("5. Record the submission date and any later responses separately.\n\n")
                append("Requested action: direct the official mechanism to process a deletion request for eligible, non-exempt data-broker information.\n")
                append("This checklist is not a submission receipt or proof of deletion.")
            }
        }

        return RightsRequestDraft(
            jurisdiction = jurisdiction,
            right = right,
            controllerName = normalizedController,
            scopeDescription = scope,
            preparedOn = preparedOn,
            receivedOn = receivedOn,
            standardResponseDueOn = deadline,
            extendedResponseDueOn = extended,
            responsePeriodNote = periodNote,
            officialGuidanceUrl = jurisdiction.officialGuidanceUrl,
            message = message
        )
    }

    fun canTransition(from: RightsRequestStatus, to: RightsRequestStatus): Boolean = when (from) {
        RightsRequestStatus.DRAFT -> to == RightsRequestStatus.REVIEWED
        RightsRequestStatus.REVIEWED -> to == RightsRequestStatus.DRAFT || to == RightsRequestStatus.SUBMITTED
        RightsRequestStatus.SUBMITTED -> to == RightsRequestStatus.ACKNOWLEDGED || to == RightsRequestStatus.RESPONSE_RECEIVED
        RightsRequestStatus.ACKNOWLEDGED -> to == RightsRequestStatus.RESPONSE_RECEIVED
        RightsRequestStatus.RESPONSE_RECEIVED -> to == RightsRequestStatus.OUTCOME_REPORTED
        RightsRequestStatus.OUTCOME_REPORTED -> false
    }
}
