# Privacy-rights request assistant: behavior and legal boundaries

**Source review date:** 27 October 2026  
**Status:** local draft/tracker implementation; not legal advice or a submission service.

## What the Android workflow does

The rights assistant builds a draft in memory, gives the user the official guidance URL, and optionally copies the draft to the clipboard. It never sends the request. Its local tracker saves only the selected jurisdiction/right, controller name if supplied, preparation date, user-reported receipt date, planning dates, status and official guidance URL. It does not save the draft body, a user's name/email, identity documents, or receipt text.

Tracker states are user-reported process stages, not independently verified facts:

- `DRAFT` → `REVIEWED` → `SUBMITTED` → `ACKNOWLEDGED` → `RESPONSE_RECEIVED` → `OUTCOME_REPORTED`.
- The allowed transitions do not let a new draft jump straight to submitted.
- A user may delete one record or clear tracker metadata. This does not send a request or affect data held by a controller.
- The UI says “not submitted” after generating/copying a draft. Opening a guidance URL is not treated as submission.

## Configured planning rules

### UK GDPR — current official ICO guidance

The ICO's erasure guidance, accessed 27 October 2026, says a controller must respond without undue delay and no later than one calendar month after receipt (with timing nuances such as identity-verification requests). It may extend by a further two months for complexity or numerous requests, but must notify the person within the first month and explain why. The deadline is calendar-month arithmetic—not a fixed 30 days. If the month lacks the corresponding date, the end of that month applies; a weekend/bank holiday can shift the end to the next working day.

The app currently uses `LocalDate.plusMonths(1)` for a standard planning date and `plusMonths(3)` when the user manually records that an extension notice was received. This intentionally does **not** compute bank holidays or claim to decide whether an extension is lawful. The user should check the official guidance and request correspondence.

Official source: [ICO — Right to erasure](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/).

### California CCPA/CPRA — 2026 regulations

The CPPA's CCPA text effective 1 January 2026 provides a 45-calendar-day response period for covered deletion, correction, know and specified access requests. Where necessary, a covered business may take up to a further 45 calendar days with notice and an explanation, up to 90 calendar days total. Eligibility, verification, exceptions, request type and applicable rules matter. The draft workflow uses a 45-day planning date from the date the user records as receipt; the optional extension date is only added after the user confirms a notice. It is not a legal determination.

Official sources:
- [CPPA — CCPA statute effective 1 January 2026 (PDF)](https://cppa.ca.gov/regulations/pdf/ccpa_statute_eff_20260101.pdf)
- [CPPA — Frequently asked questions](https://cppa.ca.gov/faq).

### California DROP — user-guided only

The assistant opens official CPPA data-broker guidance and provides a checklist for the user to complete the official service themselves. PrivaCage does not directly submit, query, scrape or automate the DROP service. The official materials say that beginning 1 August 2026 data brokers must access the platform at least once every 45 days; this is a broker operational duty, not a promise that a specific user's request will be completed within 45 days.

Official source: [CPPA — Information for data brokers / DROP](https://www.cppa.ca.gov/data_brokers/).

## Safety, privacy and release requirements

- Never auto-send a request, silently attach identity documents, or transmit personal information during onboarding.
- Verify that the selected legal entity and contact route appear in the controller's official privacy notice before sending manually.
- Explain potential account/service consequences and exceptions before a user sends a deletion request.
- Don't call a company response “verified deletion.” A controller's claim, a submission receipt and an independent technical verification are different evidence.
- The tracker keeps only metadata. If the user wants to retain sensitive correspondence, that requires a separate explicit design with encryption, field-level minimization, retention controls and delete/export behavior.
- Dates remain planning aids and don't model public holidays, all identity verification timing, controller-specific extensions, jurisdiction/eligibility, or every exception.

**Release blocker:** the copy and rules need review by a qualified privacy-law reviewer before being presented as jurisdiction-specific legal advice. Recheck official source text on every release; do not assume current deadlines will remain unchanged.
