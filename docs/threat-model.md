# Initial Threat Model

This is a working threat model, not a security audit. Update it as executable components are added.

## Assets

- User network metadata and app-usage patterns.
- Local audit logs, rule choices, and exported reports.
- APKs selected for scanning and metadata extracted from them.
- Legal-request drafts and personal identifiers entered by the user.
- Integrity of tracker signatures and update packages.
- Trust in the accuracy of product warnings.
- App package names, app-open timestamps, and user-supplied policy links in the local review queue.
- Transient Android monitoring-access observations shown on the review screen.

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
- A user mistakes a bounded Usage Access observation window for a complete app-usage history.
- A user interprets a legitimate accessibility service, device administrator, notification listener, or VPN as proof of abuse.

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

## Additional mitigations

- Require the user's Usage Access grant, inspect only launcher-visible packages, bound app-open queries to the most recent 24 hours, and describe the result as partial rather than a complete usage history.
- The monitoring-access review is user-triggered, reads only four documented Android settings surfaces, does not persist or upload its results, and presents benign use cases and uncertainty beside each observation.
- Never disable an accessibility service, administrator, notification listener, or VPN automatically; a settings handoff is not a recommendation to change access.

## Non-goals and limits

- Protection against a fully compromised OS, kernel, baseband, or malicious firmware.
- Blocking every manufacturer or carrier telemetry path on stock devices.
- Seeing arbitrary HTTPS contents without an explicitly configured interception mechanism.
- Preventing an app from sending data over an allowed connection when that data is not visible to the filter.
- Guaranteeing anonymity, eliminating all fingerprinting, or preventing all network correlation.
- Verifying deletion from a third party's systems without reliable evidence from that party or an independent audit.

## Safety considerations

Stalkerware signals must be framed carefully: an enabled accessibility service, active administrator, notification listener, or VPN is a review signal, not conclusive proof of abuse. The stock review does not identify who enabled a setting or what a service does. Safety guidance must be cautious because removing software or changing settings can alert a person with device-management access or put a user at greater risk. The review has no automatic removal, notification, persistence, upload, or forced share path.


## No-telemetry, legal-process and local-encryption risks

| Asset / process | Threat | Mitigation and remaining boundary |
|---|---|---|
| Local DNS settings, rights tracker and permission baseline | Device storage inspection or offline file modification | Separate AES-256-GCM encrypted preference envelopes, per-purpose Android Keystore keys and authenticated purpose labels. Authentication failures preserve ciphertext. This does not protect plaintext in memory, a rooted/compromised OS, unlocked-device access, or every operational preference. |
| Permission audit evidence | Missing metadata is mistaken for a negative result, or an unusually large package inventory consumes excessive resources or is truncated into a false comparison | Unresolved protection levels and missing/misaligned grant flags are reported as unknown. Scanning is capped at 512 declared permissions per package and 50,000 declarations per scan; any cap hit marks the scan incomplete and blocks comparison/baseline replacement. The encrypted snapshot is also checked against the 4 MiB, 2,000-package, 256-dangerous-permission-per-package and name limits before comparison. The prior encrypted baseline is preserved on every incomplete/over-limit path. This still covers only launcher-visible packages and Android-exposed metadata. |
| Product telemetry | Analytics/crash SDK or custom source code added by a future dependency/change | Strict no-telemetry policy and CI scan across Android Gradle dependencies, main Kotlin/Java/XML source and manifest. Manual review remains necessary for unknown SDKs, hand-written requests, platform/OEM diagnostics and transitive behaviour outside the marker list. |
| Functional network requests | DNS resolver, relay, reverse proxy or host observes information needed for the feature | Explicit destination selection/confirmation where appropriate; DNS and sync data boundaries are documented. Provider/host policies and logs remain outside the local client. Relay content is encrypted, but metadata is visible. |
| Legal demand | Operator is required by applicable law to provide information it holds | No voluntary disclosure; review validity/jurisdiction/scope, challenge or narrow where legally available, disclose only the minimum held data legally required, and notify when lawful/safe. No claim of immunity from valid legal process. |
| Local key loss | Keystore key invalidated, removed or unavailable | Never generate a replacement for an existing ciphertext record. Preserve the ciphertext and report the error; independent encrypted export/recovery is required where available. |

The project does not build an authority-access API or maintain a central PrivaCage user-account dataset. App-policy review links and status remain in the encrypted local queue; the app does not transmit policy contents. A separately hosted relay or public web endpoint may have ordinary connection metadata under its operator's control. DNS resolvers and user-configured relay hosts are separate recipients. Their own legal obligations and disclosures cannot be controlled by the PrivaCage client.
