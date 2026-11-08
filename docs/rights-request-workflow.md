# Privacy-rights request assistant: behavior and legal boundaries

**DROP consumer-source review:** 8 November 2026. **UK GDPR/CCPA deadline-source review:** 27 October 2026.  
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

The assistant now opens the **consumer-facing CalPrivacy DROP landing page** at [privacy.ca.gov/drop](https://privacy.ca.gov/drop/), which links directly to the official consumer service. The previous `cppa.ca.gov/data_brokers/` URL is a broker-facing information page, not the consumer entrypoint. The checklist states that DROP eligibility is limited to California residents and asks the user to review the official identity-verification and data-handling notices before entering any information. The user chooses what to provide on the official site; PrivaCage does not collect, submit, query, scrape or automate the service.

CalPrivacy's consumer guidance says data brokers began processing requests on 1 August 2026, must access DROP at least once every 45 days, and may take up to 90 days for status updates to appear. The 45-day cycle is a broker operational duty, not an individual response deadline; the 90-day statement is the agency's current status-update guidance, not a guarantee that every broker will report a particular outcome by that date. The user should check their own DROP profile for current status.

Official sources: [CalPrivacy — DROP landing page](https://privacy.ca.gov/drop/) and [How DROP works](https://privacy.ca.gov/drop/how-drop-works/).

## Local tracker integrity

The local JSON reader requires the exact stored-record schema and strict field types. It accepts only canonical UUIDs and ISO calendar dates, unique record IDs, trimmed controller names without control characters, and the exact official guidance URL configured for the selected jurisdiction. Existing California DROP records using the previous broker-facing URL are normalized to the consumer entrypoint when read and rewritten on the next successful tracker save; no record or status is discarded. For direct UK GDPR and California CCPA/CPRA requests, the reader recomputes the configured calendar-month or 45/90-day planning dates from the user-reported receipt date and rejects mismatches; California DROP records never carry an individual response deadline. Every write passes through the same strict reader before the preferences commit, with 100-record and 512 KiB limits enforced. The reader continues to accept legacy records in which the previous Android JSON writer omitted nullable keys, then writes those values in explicit-null form on the next successful save. It rejects oversized, over-count, duplicate-key, malformed or inconsistent data and preserves the stored value rather than treating it as an empty tracker.

These checks protect against malformed or unexpectedly edited local records and prevent a stored guidance link from redirecting the user to an unrelated HTTPS host. They are not cryptographic tamper evidence and do not protect against a compromised operating system or a process with access to the app's private data.

## Safety, privacy and release requirements

- Never auto-send a request, silently attach identity documents, or transmit personal information during onboarding.
- Verify that the selected legal entity and contact route appear in the controller's official privacy notice before sending manually.
- Explain potential account/service consequences and exceptions before a user sends a deletion request.
- Don't call a company response “verified deletion.” A controller's claim, a submission receipt and an independent technical verification are different evidence.
- The tracker keeps only metadata. If the user wants to retain sensitive correspondence, that requires a separate explicit design with encryption, field-level minimization, retention controls and delete/export behavior.
- Dates remain planning aids and don't model public holidays, all identity verification timing, controller-specific extensions, jurisdiction/eligibility, or every exception.

**Release blocker:** the copy and rules need review by a qualified privacy-law reviewer before being presented as jurisdiction-specific legal advice. Recheck official source text on every release; do not assume current deadlines will remain unchanged.
