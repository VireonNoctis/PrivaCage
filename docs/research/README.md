# PrivaCage Research Library

**Research baseline:** 25 October 2026  
**Purpose:** turn the PrivaCage concept into a technically honest, evidence-backed privacy roadmap.

This library is deliberately not a claim that every described capability is already implemented. It separates platform facts, engineering conclusions, candidate features, and unresolved questions. Each research note should be reviewed when operating-system behavior, law, or source material changes.

## Reading order

1. [Threat model and privacy landscape](01-threat-model-and-privacy-landscape.md) — threats worth solving and a realistic definition of success.
2. [Android capability audit](02-android-platform-capabilities.md) — what an ordinary Android app, VPN service, and privileged/root component can each do.
3. [iOS capability audit](03-ios-platform-capabilities.md) — Network Extension, App Privacy Report, and App Store constraints.
4. [Network visibility and blocking](04-network-visibility-and-blocking.md) — DNS, encrypted protocols, attribution, fail-open/fail-closed, and rule safety.
5. [App scanning and privacy labels](05-app-analysis-and-privacy-labels.md) — APK analysis, SDK signatures, confidence and false positives.
6. [Identifiers, fingerprinting and metadata](06-identifiers-fingerprinting-metadata.md) — ad IDs, browser fingerprinting, EXIF, and feasible controls.
7. [Data brokers and rights requests](07-data-brokers-and-rights-engine.md) — GDPR/UK GDPR, California CCPA timelines, California DROP, and safe submission workflows.
8. [Anomaly detection](08-anomaly-detection.md) — useful behavioral signals without pretending an anomaly proves misconduct.
9. [Stalkerware and coercive monitoring](09-stalkerware-safety.md) — a safety-first design, including situations where revealing a scan could increase danger.
10. [Secure-by-design data lifecycle](10-secure-by-design-data-lifecycle.md) — PrivaCage's own privacy budget, local logs, encryption and threat containment.
11. [Recommended-apps governance](11-recommended-apps-governance.md) — how the directory earns and loses trust.
12. [Roadmap](12-roadmap.md) — ranked implementation plan and explicit blockers.
13. [Verification plan](13-verification-plan.md) — tests, evidence requirements, acceptance criteria, and adversarial review.
14. [Assumption audit](14-assumption-audit.md) — high-impact claims in the initial idea that need rewording or gating.
15. [Android local-history encryption](15-android-local-history-encryption.md) — encrypted DNS-history storage, migration behavior, failure cases, and the device-validation checklist.
16. [Sources](SOURCES.md) — annotated source register with stable links.

## Evidence labels

Use these labels consistently in implementation notes and UI copy:

- **Platform fact** — directly supported by official platform/API documentation or a primary legal source.
- **Observed signal** — something the installed build actually measured (for example, a DNS query seen by the local tunnel).
- **Static indicator** — a pattern found in an APK or metadata (for example, a known tracker SDK signature); it is not proof of runtime behavior.
- **Inference** — a reasoned conclusion from several observations, with confidence and alternative explanations.
- **User-reported** — information entered by the user or imported from a report; do not present it as independent verification.
- **Unavailable** — the platform does not expose the signal to this build, the observation failed, or attribution was ambiguous.

Do not upgrade an inference or static indicator to a fact merely because the UI needs a simpler sentence.

## Research rules

- Prefer first-party platform documentation, standards, primary legal texts and regulator guidance. Use independent tools such as Exodus Privacy as design references, not as infallible ground truth.
- Distinguish **can access**, **did access**, **sent off-device**, **was observed on the network**, and **was blocked**. These are different propositions requiring different evidence.
- Every detector needs a stated input, limitations, confidence rule, failure behavior and a test case.
- No feature may claim to inspect all app API calls on stock devices unless an actual platform interface supplies those events.
- No network hostname, SDK presence or unusual timing alone proves that personal data was collected or misused.
- Do not upload device inventories, domains, crash logs, legal-request identities or event histories by default.
- Keep privileged/root functionality as a separate, explicit threat model. Never simulate the result of a privileged operation on a non-privileged build.
- Legal material is product research, not legal advice. Jurisdiction, controller identity, eligibility, exceptions and procedural rules must be checked for each template before use.

## Scope boundary

The first useful release should prioritize Android APK inspection, local VPN-based domain/IP telemetry with honest attribution, safe rule-based blocking, explainable local anomaly detection, a consent/permission audit history, and a user-reviewed legal-request workflow. iOS should begin with user-guided interpretation of Apple's own privacy surfaces plus portable privacy utilities. Anything that needs root, special Apple entitlement approval, enterprise management, browser ownership, or a third-party platform API is labelled accordingly.

## Source maintenance

The sources were checked on 25 October 2026. The dates shown refer to source publication/effective status where available, not a promise that the linked page will remain unchanged. Before a legal template or OS-specific implementation ships, re-open the current official source and add a review date to the corresponding implementation issue.