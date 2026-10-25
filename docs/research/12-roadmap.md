# 12 — Research-Driven Product Roadmap

**Research baseline:** 25 October 2026  
**Principle:** the smallest release that delivers real privacy value beats a broad dashboard full of unverified claims.

## 1. Capability tiers

- **Tier 0 — foundation:** event schema, provenance labels, local storage/retention, capability matrix, test fixtures, source-reviewed tracker database.
- **Tier 1 — stock Android baseline:** user-selected APK scan, manifest/SDK signatures, local VPN network events, app attribution where verifiable, DNS/endpoint blocking, transparent VPN state, local permission guidance, explainable rules.
- **Tier 2 — practical privacy actions:** metadata scrubber for tested formats, legal rights request drafts/tracking, advertising-ID and system-setting guidance, privacy-respecting app directory, local anomaly alerts.
- **Tier 3 — specialized platform work:** root/system extensions, advanced AppOps controls, browser/WebView privacy features, richer iOS Network Extension support after entitlement validation, device/OEM-specific studies.
- **Tier 4 — optional sync and research:** opt-in E2E-encrypted sync, reproducible aggregate research with explicit consent, offline breach corpus if source/license/freshness are suitable.

## 2. Recommended execution sequence

### Milestone A — credibility baseline

**Deliverables:** amend architecture/README claims, capability matrix, structured evidence model, threat model, retention policy, verification suite skeleton.

**Exit criteria:** every event type has a source and supported platform/privilege; unsupported events cannot appear as successes; local-only claims pass outbound-traffic inspection.

### Milestone B — Android network MVP

**Deliverables:** `VpnService` tunnel, DNS/flow parsing, rules engine, active-state diagnostics, attribution confidence, Normal log, local ruleset and kill-switch semantics.

**Exit criteria:** controlled fixtures verify pass/block behavior; IPv4/IPv6 and VPN revocation tested; no API-call/sensor events inferred from packets; unknown UID cases remain visible as unknown.

**Explicit limitation:** do not call this “every app action in real time.” It is routed network activity plus whatever independent public OS state is explicitly integrated.

### Milestone C — APK analysis and privacy labels

**Deliverables:** user-selected APK workflow, manifest parser, SDK signatures, scan metadata/hash, limitations/citations, output schema and false-positive review flow.

**Exit criteria:** reproducible scans; unsupported/malformed inputs fail visibly; signature database has evidence, tests and versioning; no blanket “safe/clean” result.

### Milestone D — practical file and permission controls

**Deliverables:** permission status/Settings handoff, verification after return, share-sheet metadata scrubber with supported-format list and output re-parse.

**Exit criteria:** no fake permission toggle; metadata fields disappear in tested output and originals stay untouched; partial failures are reported.

### Milestone E — rights engine v1

**Deliverables:** locally rendered request drafts, user-review-before-send, GDPR/UK GDPR and California request timelines as separately configured rules, evidence/receipt handling, reminder and escalation checklist.

**Exit criteria:** legal review complete; calendar-month semantics tested; no automated claims of successful deletion; no automatic send during onboarding; supported routes are documented and rechecked.

**Current opportunity:** user-guided California DROP workflow from the official CPPA mechanism, with no assumed undocumented API ([S23](SOURCES.md#s23), [S24](SOURCES.md#s24)).

### Milestone F — anomaly alerts and recommended apps

**Deliverables:** deterministic local baseline, explainable alert reason codes, evidence drill-down; vetted app directory with dated evidence and review status.

**Exit criteria:** alert quality measured on fixtures; static and runtime evidence separate; recommendations include trade-offs and can be suspended/reviewed quickly.

### Milestone G — iOS companion

**Deliverables:** privacy-settings assistant, App Privacy Report interpretation workflow, disclosures comparison, metadata scrubber and rights engine; network extension only if entitlement/behavior validation succeeds.

**Exit criteria:** no unsupported cross-app API claims; App Privacy Report import source/window is explicit; all network extension entitlements/deployment restrictions documented.

### Milestone H — privileged extensions (optional)

**Deliverables:** root-only AppOps/process hook prototype and per-device support matrix where feasible.

**Exit criteria:** independent security review; rollback, device compatibility and failure modes tested; the stock app remains correct without the extension; user understands the additional attack surface.

## 3. Priority ranking by impact / feasibility

| Rank | Feature | Impact | Feasibility | Key caveat |
|---|---|---|---|---|
| 1 | Correct local network monitor/blocker | High | Medium | Hostname and UID visibility incomplete |
| 2 | APK static analysis with honest labels | High | Medium | Static signatures do not prove activity |
| 3 | On-device file metadata scrubber | High | High for limited formats | Must verify output per format |
| 4 | Rights request engine + California DROP guidance | High | Medium | Law, eligibility and supported submission paths change |
| 5 | Clear privacy settings/identifier guidance | Medium | High | Guide/link, not universal automation |
| 6 | Local anomaly alerts | Medium | Medium | False positives and changing app versions |
| 7 | Stalkerware safety review | High impact | Medium/low | High safety and false-positive risk; specialist review required |
| 8 | Root-only API interception | Potentially high | Low/fragmented | Fragile, privilege-specific, high attack surface |
| 9 | Full iOS cross-app surveillance | Not a valid baseline promise | Unsupported as described | Platform API/entitlement constraints |

## 4. Defer until a specific blocker is solved

- Automatic modification of third-party permissions on ordinary Android.
- Fake/empty sensor/clipboard/contact injection without a verified privilege boundary.
- “Detects every sensor or clipboard read” on stock Android/iOS.
- Universal browser fingerprint randomization across third-party apps.
- Uploading all logs to a cloud dashboard for “AI analysis.”
- Automatic deletion requests sent to many companies without reviewing identity/data exposure.
- A system-wide IoT scanner before the network monitor's coverage and isolation assumptions are tested.
- ML-based behavior scoring before rule-based precision is known.

## 5. Adjacent features worth exploring after core validation

1. **EXIF/document metadata scrubber:** buildable today for explicitly supported formats, with share-sheet integration and file-level output verification.
2. **California DROP helper:** buildable now as a guided workflow; a programmatic integration requires a verified supported interface.
3. **Local breach exposure checker:** potentially useful, but requires a lawful/fresh corpus or privacy-preserving query protocol and must not leak the email being checked.

These are not substitutes for verifying the core VPN, scanner and data-retention behavior.

## 6. Project health metrics

Track:

- supported devices/OS versions tested, not only code coverage;
- attribution coverage and number of unknown events;
- block false positives/false negatives in controlled tests;
- scan reproducibility and signature aging;
- retention/deletion behavior in real databases;
- percentage of request templates with current source review;
- crash rate and battery/throughput cost of VPN processing;
- safety and privacy review completion for sensitive features.

Do not use number of domains blocked, alerts generated or “trackers found” as a primary success metric: higher counts may simply indicate more noise.