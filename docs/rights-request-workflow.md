# Privacy-rights request assistant: behavior and legal boundaries

**DROP consumer-source review:** 8 November 2026. **CCPA response-period review:** 28 November 2026. **UK GDPR source review:** 27 October 2026.  
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

The CPPA's 2026 regulations separate these request types:
- Delete, correct and know: the business must confirm receipt no later than 10 business days after receipt (unless already granted or denied), then substantively respond within 45 calendar days of receipt. Section 7021(b) says the 45-day period begins on the receipt date, so the planning date counts that date as day one. A further 45 calendar days may be used when necessary and after notice, for a maximum 90-calendar-day period also counted from the receipt date. The tracker calculates both a 10-business-day receipt-confirmation planning date and the 45-calendar-day response planning date; an extension date appears only after the user records that notice was received.
- Sale/sharing opt-out: the business must comply as soon as feasibly possible and no later than 15 business days after receipt. No 10-business-day confirmation or 45/90-day response calculation is applied.
- Right to limit sensitive-personal-information use/disclosure: this is a distinct right under Civil Code §1798.121 and 11 CCR §7027, not a sale/sharing opt-out. It applies only when the business uses or discloses sensitive personal information for purposes outside the regulatory exceptions. The business must comply as soon as feasibly possible and no later than 15 business days after receipt. No 10-business-day confirmation or 45/90-day response calculation is applied.

For sale/sharing opt-out and right-to-limit requests, the regulations do not require a verifiable consumer request; a business may ask only for information necessary to direct the request. The app does not ask users to attach identity documents by default. The app displays these dates in the draft and local tracker only; it does not schedule OS notifications or send follow-up messages. The app's 10- and 15-business-day dates count Monday-Friday only and do not model California state holidays or business closures. These are planning reminders, not legal determinations. The business may need to act sooner when feasible, and eligibility, exceptions, verification, request type and current law still matter.

Official sources:
- [CPPA — CCPA statute effective 1 January 2026 (PDF)](https://cppa.ca.gov/regulations/pdf/ccpa_statute_eff_20260101.pdf)
- [CPPA — Frequently asked questions](https://cppa.ca.gov/faq.html).

The Android model now represents LIMIT_SENSITIVE separately from OPT_OUT, uses the 15-business-day maximum for both, and calculates the separate 10-business-day receipt-confirmation reminder only for delete/correct/know requests. The tracker remains user-reported and local-only; it does not submit requests or verify controller compliance.

### California DROP — user-guided only

The assistant now opens the **consumer-facing CalPrivacy DROP landing page** at [privacy.ca.gov/drop](https://privacy.ca.gov/drop/), which links directly to the official consumer service. The previous `cppa.ca.gov/data_brokers/` URL is a broker-facing information page, not the consumer entrypoint. The checklist states that DROP eligibility is limited to California residents and asks the user to review the official identity-verification and data-handling notices before entering any information. The user chooses what to provide on the official site; PrivaCage does not collect, submit, query, scrape or automate the service. CalPrivacy explicitly says not to share the DROP ID: PrivaCage has no DROP-ID field and does not store it. Keep the ID private and use the official profile to check status. The official help page also explains that a request may be made for another person in permitted cases (for example, a parent for a child); the residency of the person whose request is being made must be verified, and the official representative instructions control.

CalPrivacy says data brokers began processing DROP requests on 1 August 2026 and must access the platform at least once every 45 days. After initial processing, brokers must re-check and delete newly matching data at least every 45 days. Its November 2026 consumer page says brokers should by then have completed their initial download/upload cycle; status updates may still take up to 90 days and vary by broker. These are broker processing and reporting windows, not an individual consumer response deadline or a guarantee. The user should check their own DROP profile for current status.

Official sources: [CalPrivacy — DROP landing page](https://privacy.ca.gov/drop/) and [How DROP works](https://privacy.ca.gov/drop/how-drop-works/).

## Local tracker integrity

The local JSON reader requires the exact stored-record schema and strict field types. It accepts only canonical UUIDs and ISO calendar dates, unique record IDs, trimmed controller names without control characters, and the exact official guidance URL configured for the selected jurisdiction. Existing California DROP records using the previous broker-facing URL are normalized to the consumer entrypoint when read and rewritten on the next successful tracker save; no record or status is discarded. For direct UK GDPR and California CCPA/CPRA requests, the reader recomputes the configured calendar-month, 45/90-day, 15-weekday, and 10-weekday acknowledgement-reminder dates from the user-reported receipt date and rejects mismatches. Legacy encrypted tracker records without the acknowledgement field remain readable and are normalized in memory; the next successful save writes the current field. The distinct right-to-limit record uses the 15-weekday path and never receives a 10-day acknowledgement or 45/90-day extension. Legacy CCPA sale/sharing opt-out records containing the previous 45/90-day calculation are normalized in memory to the 15-business-day planning date and rewritten on the next successful tracker save. California DROP records never carry an individual response deadline, and the UI does not offer a new individual controller receipt-date field for DROP. Any pre-existing user-entered DROP receipt date remains preserved as read-only legacy metadata. Every write passes through the same strict reader before the preferences commit, with 100-record and 512 KiB limits enforced. The reader continues to accept legacy records in which the previous Android JSON writer omitted nullable keys, then writes those values in explicit-null form on the next successful save. It rejects oversized, over-count, duplicate-key, malformed or inconsistent data and preserves the stored value rather than treating it as an empty tracker.

These checks protect against malformed or unexpectedly edited local records and prevent a stored guidance link from redirecting the user to an unrelated HTTPS host. They are not cryptographic tamper evidence and do not protect against a compromised operating system or a process with access to the app's private data.

## Safety, privacy and release requirements

- Never auto-send a request, silently attach identity documents, or transmit personal information during onboarding.
- Verify that the selected legal entity and contact route appear in the controller's official privacy notice before sending manually.
- Explain potential account/service consequences and exceptions before a user sends a deletion request.
- Don't call a company response “verified deletion.” A controller's claim, a submission receipt and an independent technical verification are different evidence.
- The tracker keeps only metadata. If the user wants to retain sensitive correspondence, that requires a separate explicit design with encryption, field-level minimization, retention controls and delete/export behavior.
- Dates remain planning aids. CCPA 10- and 15-business-day calculations count Monday-Friday only; they do not model California state holidays or business closures. No calculation models every identity-verification timing, controller-specific circumstance, jurisdiction/eligibility rule, or exception.

**Release blocker:** the copy and rules need review by a qualified privacy-law reviewer before being presented as jurisdiction-specific legal advice. Recheck official source text on every release; do not assume current deadlines will remain unchanged.
