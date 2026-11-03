# Initial Threat Model

This is a working threat model, not a security audit. Update it as executable components are added.

## Assets

- User network metadata and app-usage patterns.
- Local audit logs, rule choices, and exported reports.
- APKs selected for scanning and metadata extracted from them.
- Legal-request drafts and personal identifiers entered by the user.
- Integrity of tracker signatures and update packages.
- Trust in the accuracy of product warnings.

## Threats

- A signature falsely labels a benign service or misses a new tracker.
- Malformed APKs or packets exploit a parser.
- An attacker poisons tracker data or update packages.
- Logs reveal sensitive habits on a shared, backed-up, or compromised device.
- A user assumes a blocked DNS name means all telemetry is blocked.
- A control reports success when the OS denied it.
- A malicious PrivaCage update collects data.
- Recommendations are manipulated by commercial incentives.
- A legal workflow implies that a company deleted data when it has not.

## Mitigations

- Evidence URLs, verification dates, stable IDs, review status, and human review.
- Strict input validation, bounded parsing, fuzz tests for packet/APK parsers, and dependency minimization.
- DNS upstream responses are checked for matching transaction ID and question, structurally valid resource records, valid compression-pointer bounds, declared RDATA lengths, and unexpected trailing bytes.
- Truncated upstream UDP DNS replies are retried over a protected TCP socket; a missing/failed protection callback causes an explicit failure rather than an unprotected connection.
- An upstream DNS failure drops the affected query without intentionally stopping the whole VPN service or inventing a response.
- Signed releases and authenticated update metadata before automatic updates.
- Local-only storage by default, limited event fields, retention controls, and explicit export.
- Separate observed facts from static indicators and inferences.
- Verify enforcement outcomes through the OS and surface failures.
- Require evidence for app recommendations and prohibit paid placement.
- Track request-submission evidence separately from company responses and confirmed deletion.

- API provider credentials and the text selected for remote analysis.
- App package names, app-open timestamps, and user-supplied policy links in the local review queue.
- A provider or model processing submitted text beyond the user's expectation.
- A malicious or compromised app process reading an API key while it is in memory.

## Additional mitigations

- Encrypt API credentials and the app policy review queue with independent AES-GCM envelopes and Android Keystore keys; keep them out of sync and backup.
- Keep provider endpoints fixed and HTTPS-only, refuse redirects, bound request/response sizes, avoid logging credentials or provider response bodies, and require per-task permission plus an explicit per-request confirmation.
- Do not give models tool declarations or an execution bridge; model output is explanatory text or a draft only.
- Disclose that provider-side processing is outside PrivaCage's local storage controls and that Android Keystore cannot protect secrets against a compromised OS or a malicious process with access to the app's runtime.

## Non-goals and limits

- Protection against a fully compromised OS, kernel, baseband, or malicious firmware.
- Blocking every manufacturer or carrier telemetry path on stock devices.
- Seeing arbitrary HTTPS contents without an explicitly configured interception mechanism.
- Preventing an app from sending data over an allowed connection when that data is not visible to the filter.
- Guaranteeing anonymity, eliminating all fingerprinting, or preventing all network correlation.
- Verifying deletion from a third party's systems without reliable evidence from that party or an independent audit.

## Safety considerations

Stalkerware signals must be framed carefully: a hidden icon, unusual accessibility permission, or persistence behavior is a review signal, not conclusive proof of abuse. Safety guidance must be cautious because removing software or changing settings can alert an abuser or put a user at greater risk.


## No-telemetry, legal-process and local-encryption risks

| Asset / process | Threat | Mitigation and remaining boundary |
|---|---|---|
| Local DNS settings, rights tracker and permission baseline | Device storage inspection or offline file modification | Separate AES-256-GCM encrypted preference envelopes, per-purpose Android Keystore keys and authenticated purpose labels. Authentication failures preserve ciphertext. This does not protect plaintext in memory, a rooted/compromised OS, unlocked-device access, or every operational preference. |
| Product telemetry | Analytics/crash SDK or custom source code added by a future dependency/change | Strict no-telemetry policy and CI scan across Android Gradle dependencies, main Kotlin/Java/XML source and manifest. Manual review remains necessary for unknown SDKs, hand-written requests, platform/OEM diagnostics and transitive behaviour outside the marker list. |
| Functional network requests | DNS resolver, AI provider, relay, reverse proxy or host observes information needed for the feature | Explicit destination selection/confirmation where appropriate; DNS and AI content boundaries are documented. Provider/host policies and logs remain outside the local client. Relay content is encrypted, but metadata is visible. |
| Legal demand | Operator is required by applicable law to provide information it holds | No voluntary disclosure; review validity/jurisdiction/scope, challenge or narrow where legally available, disclose only the minimum held data legally required, and notify when lawful/safe. No claim of immunity from valid legal process. |
| Local key loss | Keystore key invalidated, removed or unavailable | Never generate a replacement for an existing ciphertext record. Preserve the ciphertext and report the error; independent encrypted export/recovery is required where available. |

The project does not build an authority-access API or maintain a central PrivaCage user-account dataset. A separately hosted relay or public web endpoint may have ordinary connection metadata under its operator's control. Third-party AI providers and DNS resolvers are separate recipients. Their own legal obligations and disclosures cannot be controlled by the PrivaCage client.
