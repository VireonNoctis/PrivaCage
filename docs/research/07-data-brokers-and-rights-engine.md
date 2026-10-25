# 07 — Data Brokers and Data-Subject Rights Engine

**Research status:** regulator/primary-law review, 25 October 2026  
**Decision this note supports:** deliver a useful request workflow without mis-stating the law or falsely claiming deletion.

> This is engineering research, not legal advice. Before release, each jurisdiction template needs review by a qualified person, current source links and a visible eligibility explanation.

## 1. Separate request creation, delivery and outcome

The product must represent the following stages separately:

1. **Prepared:** a template was generated locally.
2. **Reviewed:** the user confirmed identity fields, company/controller, right invoked and submission route.
3. **Submitted:** evidence confirms an email sent or a web form produced a submission confirmation. Opening a URL is not submission.
4. **Acknowledged:** the organisation acknowledged receipt or provided a tracking reference.
5. **Response received:** the user imported or recorded a response.
6. **Outcome reported:** organisation claims to have complied, refused or partly complied.
7. **Outcome verified / unverified:** actual verification should be rare; a company's statement alone is not independent proof of complete deletion.

Never show “your data was deleted” after generating or sending a request. A request is a legal/process action against a controller, not an RPC into its database.

## 2. EU GDPR / UK GDPR: one month, not a fixed 30 days

GDPR Article 12 requires controllers to facilitate rights requests and ordinarily respond without undue delay and within one month; the period may be extended by up to two further months for complexity or number of requests, with reasons/notice required. Article 17 establishes a right to erasure in certain circumstances, but includes exceptions. The controller may need to verify identity proportionately, and the right does not mean every record must be erased in every situation ([S19](SOURCES.md#s19), [S20](SOURCES.md#s20)).

Engineering implications:

- Store deadline rules as calendar-month arithmetic, not “30 days.”
- Record the date the controller received the request separately from the day PrivaCage created it.
- Ask only for information reasonably needed for the chosen request. Do not demand ID scans by default; if a controller requires more information, show the user the request and the risk of sending it.
- Add the controller's identity and a documented contact route. A brand name may be different from the legal entity controlling the data.
- Use jurisdiction-specific templates. Do not assume GDPR applies to a user, controller or processing operation solely because the user installs the app.
- Support extension and refusal states, including the organisation's stated basis; do not automatically call a refusal unlawful.

The UK ICO's current guidance states the response period for an erasure request is one month, with possible extension by two further months for complexity or number of requests and prompt notice to the person ([S20](SOURCES.md#s20)). EU GDPR and UK GDPR should not be flattened into one jurisdiction flag without checking the applicable regime and current regulator guidance.

## 3. California CCPA/CPRA: scope, identity and response timelines

The California Privacy Protection Agency's published CCPA text effective 1 January 2026 says covered businesses must respond to delete/correct/know requests within 45 calendar days, with up to an additional 45 days where necessary and notice/explanation are provided; the 2026 rules also specify acknowledgement within 10 business days for covered request types ([S21](SOURCES.md#s21), [S22](SOURCES.md#s22)). The statute applies only when the business and processing fall within the law's scope and the consumer is eligible. Deletion has exceptions and verification rules.

Therefore:

- Use 45 calendar days as the standard configured deadline where the current applicable CCPA rule supports it, not as a universal privacy-law deadline.
- Store the law/version and date last reviewed with every template.
- Include an optional extension event and deadline change, not an automatically extended timer for every company.
- Add identity verification as a separate workflow; don't equate a successful email delivery with verification.
- Explain that the request can be denied or partially honored under applicable exceptions.
- Make the controller and state/jurisdiction assumptions reviewable before the request is sent.

## 4. California DROP — timely opportunity

The California Privacy Protection Agency's DROP material describes a state-run mechanism for consumers to submit a single deletion request to registered data brokers for non-exempt personal information. The framework took effect on 1 January 2026. CPPA materials state that beginning 1 August 2026, data brokers must access DROP at least every 45 days to retrieve and process requests ([S23](SOURCES.md#s23), [S24](SOURCES.md#s24)).

**Buildable now:** a user-guided “California data broker deletion” workflow that explains the official state mechanism, prepares a checklist, opens the official service, and helps the user track their submission and subsequent statuses.

**Not yet established by this research:** a public, supported API that permits a third-party app to submit or query DROP requests programmatically. Do not implement an undocumented API, scrape the platform, automate CAPTCHA/identity checks, or promise a one-tap fully automated deletion without verifying official technical terms and an authorized interface.

Suggested records:

- `jurisdiction`: `US-CA`;
- `mechanism`: `CA-DROP`;
- `submission_source`: user-confirmed official website;
- `submitted_at`: set only on user confirmation / imported receipt;
- `receipt_reference`: encrypted/local if the user wants it retained;
- `broker_outcomes`: unknown unless evidence is supplied;
- `last_guidance_reviewed`: required.

DROP is complementary to individual company requests, not proof that all data brokers have been covered or all exemptions have been removed.

## 5. Company registry and request templates

Every registry entry should contain:

- canonical legal controller name, consumer-facing brand and jurisdiction;
- official privacy notice/rights page URL and date reviewed;
- documented contact route (form, email or supported API) and conditions;
- rights available and jurisdictions/eligibility caveats;
- data types/request scope and possible side effects (for example, loss of service/account deletion);
- identity verification expectations and data-minimizing alternatives;
- response deadline rule and source;
- evidence retention options and deletion schedule;
- provenance for every field and reviewer status.

Do not use a crowd-edited email address as a verified official endpoint merely because a domain looks plausible. Validate the domain against an official privacy policy or government registry, show the source to the user, and keep a route to report changes.

## 6. User review and safe sending

An automatic outbound request can reveal the user's name, email, address, account handle, device identifier or legal concern to the wrong party if the registry is wrong. The default must be draft-and-review. A user may opt into sending only after they can inspect the destination, data fields, exact message and route.

Implementation controls:

- Never auto-send deletion requests at onboarding without a clear destination-by-destination review.
- No third-party relay by default. If a relay exists, disclose metadata, retention, abuse protection and whether it can read request contents.
- Avoid attaching identity documents or precise location unless necessary and directly requested by the user after a warning.
- Encrypt any locally retained receipts; offer delete/export controls.
- Protect against duplicate submission and rate-limit accidental repeats.
- Do not silently resend a request when the first attempt's status is unknown.
- Store only delivery proof/status rather than a full copy of sensitive correspondence when possible.

## 7. Response and escalation tracking

The app can track statutory target windows and remind the user to review the source guidance or contact the relevant regulator. It should not assert a violation solely because a timer elapsed: extensions, verification requests, scope questions, holidays, exceptions and jurisdiction may matter. Escalation material should include a timeline assembled from the user's confirmed facts, not automated legal conclusions.

## 8. Legal engine test cases

- One-month calendar deadline on a month with fewer days.
- Valid extension notice received within the initial period.
- Controller asks for proportionate identity confirmation.
- Request is refused with an exception; UI doesn't label it automatically unlawful.
- Email sent but no delivery receipt; status remains uncertain.
- User opened a form but did not confirm submission; status remains prepared/reviewed.
- User moved jurisdiction or selected an inapplicable template before send.
- Company registry contact is stale or a domain changed ownership.
- Duplicate request, request cancellation, account deletion consequence and receipt removal.
- California DROP path uses the official mechanism without assuming an unsupported API.

## 9. Acceptance criteria

- The same request cannot be represented as both “sent” and “deleted” without separate evidence.
- Response deadlines are jurisdiction-specific and versioned; GDPR/UK GDPR use calendar-month semantics.
- CCPA's 2026 timeline reflects the current primary source and keeps scope/verification/exception caveats.
- The user sees exactly what data is submitted and to whom before sending.
- DROP integration remains user-guided until a documented official interface is verified.
- Every template has official sources, review date and a responsible reviewer.