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
- Password characters and derived hashes during an explicitly requested local exposure check.
- User-supplied offline password-hash range files and their claimed snapshot date.
- User-saved device privacy snapshots, including the exposed Private DNS provider hostname and PrivaCage's own declared-permission list.

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
- A user mistakes a self-asserted local manifest-attestation key for HIBP publisher identity or accepts a substituted public-key fingerprint.
- A missing, stale, truncated, or malformed password range is misreported as a clean result.
- A malicious, revoked, unstable, or remote SAF document provider returns partial or substituted bytes, or leaves temporary dataset copies behind.
- A user mistakes a password-hash corpus for an email/account breach database or treats a no-match as proof of password safety.
- A user mistakes a manually saved device-settings comparison for a continuous event history, reliable change timestamp, or attribution of who changed a setting.

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
- The local password matcher consumes a dedicated CharArray, clears it and intermediate byte arrays, opens the range through a no-follow read-only channel, captures the size from that handle, reads no more than the captured bytes, and rejects overlong records before decoding. It validates 35-character uppercase suffix records for the selected five-character prefix file, enforces strict ordering, and fails closed on missing, symbolic-link, truncated or corrupt ranges. The SAF adapter reads only a user-selected manifest and one selected range through ContentResolver, enforces byte caps while copying them into private cache, and surfaces provider errors; it does not enumerate or copy the full corpus or persist URI grants. The Activity passes a per-check CancellationSignal to metadata queries and openAssetFileDescriptor; providers may ignore it, and already-blocked client reads may still delay cleanup. The selected range must match the password-derived prefix and its manifest digest/record count before a result is returned. This limits path substitution and unbounded line allocation but does not authenticate source provenance or remote-provider behavior. Its result is explicitly limited to the supplied snapshot and is not an account-breach or password-strength verdict.

## Additional mitigations

- Require the user's Usage Access grant, inspect only launcher-visible packages, bound app-open queries to the most recent 24 hours, and describe the result as partial rather than a complete usage history.
- The monitoring-access review is user-triggered, reads only four documented Android settings surfaces, does not persist or upload its results, and presents benign use cases and uncertainty beside each observation.
- Never disable an accessibility service, administrator, notification listener, or VPN automatically; a settings handoff is not a recommendation to change access.
- The offline password attestation requires an independently supplied public-key fingerprint and describes the signature as a local-key statement only; it never treats the embedded public key as a publisher identity or proof of dataset completeness. The key has no per-use user-authentication requirement, so code executing in the app process can request signatures; the attestation does not prove the app actually performed the check.
- The device privacy timeline is off by default, saves only after an explicit user action, uses a separate purpose-bound Keystore AES-GCM envelope, and retains at most 30 records / 256 KiB. It records the device clock and only the exposed fields described in the Android guide; no background feed, actor attribution or other-app permission inventory is claimed.

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
| Local DNS settings, rights tracker, permission baseline and cellular checklist | Device storage inspection, offline modification, corrupted ciphertext, or an update overwriting unreadable data | Separate AES-256-GCM encrypted preference envelopes, per-purpose Android Keystore keys and authenticated purpose labels. Reads and replacement writes authenticate the existing envelope and validate its schema before use/overwrite; failures preserve the prior ciphertext. This does not protect plaintext in memory, a rooted/compromised OS, unlocked-device access, or every operational preference. |
| User-saved device privacy timeline and export | A Private DNS hostname or settings snapshot is exposed from local storage or a shared export, or a user mistakes a saved comparison for an event feed | A separate Android Keystore AES-256-GCM envelope protects the opt-in history; retention is 30 records / 256 KiB and only explicit Save actions create entries. The optional JSON export omits record IDs, always redacts Private DNS provider hostnames and normalizes unknown state values before preview/save. The preview warns that the file is plaintext, unsigned, not tamper-evident and may be synced by the selected provider. The timestamp is the device clock. Clear removes the stored envelope. The timeline does not identify who changed a setting, when it changed, or the state of unexposed settings; physical-device/Keystore lifecycle validation remains pending. |
| Permission audit evidence | Missing metadata is mistaken for a negative result, or an unusually large package inventory consumes excessive resources or is truncated into a false comparison | Unresolved protection levels and missing/misaligned grant flags are reported as unknown. Scanning is capped at 512 declared permissions per package and 50,000 declarations per scan; any cap hit marks the scan incomplete and blocks comparison/baseline replacement. The encrypted snapshot is also checked against the 4 MiB, 2,000-package, 256-dangerous-permission-per-package and name limits before comparison. The prior encrypted baseline is preserved on every incomplete/over-limit path. This still covers only launcher-visible packages and Android-exposed metadata. |
| Product telemetry | Analytics/crash SDK or custom source code added by a future dependency/change | Strict no-telemetry policy and CI scan across Android Gradle dependencies, main Kotlin/Java/XML source and manifest. Manual review remains necessary for unknown SDKs, hand-written requests, platform/OEM diagnostics and transitive behaviour outside the marker list. |
| Functional network requests | DNS resolver, relay, reverse proxy or host observes information needed for the feature | Explicit destination selection/confirmation where appropriate; DNS and sync data boundaries are documented. Provider/host policies and logs remain outside the local client. Relay content is encrypted, but metadata is visible. |
| Legal demand | Operator is required by applicable law to provide information it holds | No voluntary disclosure; review validity/jurisdiction/scope, challenge or narrow where legally available, disclose only the minimum held data legally required, and notify when lawful/safe. No claim of immunity from valid legal process. |
| Local key loss | Keystore key invalidated, removed or unavailable | Normalize expected Keystore `GeneralSecurityException` and provider `ProviderException` failures into explicit I/O errors. Preserve ciphertext on read and replacement-write failures; never generate a replacement key while accessing an existing encrypted record. Writes authenticate and schema-validate the old envelope before replacement. An explicit clear is required to discard unreadable data; independent encrypted export/recovery is required where available. |

The project does not build an authority-access API or maintain a central PrivaCage user-account dataset. App-policy review links and status remain in the encrypted local queue; the app does not transmit policy contents. A separately hosted relay or public web endpoint may have ordinary connection metadata under its operator's control. DNS resolvers and user-configured relay hosts are separate recipients. Their own legal obligations and disclosures cannot be controlled by the PrivaCage client.


## Offline password exposure lookup

| Asset / process | Threat | Mitigation and remaining boundary |
|---|---|---|
| Password characters and local Pwned Passwords range data | Password remains in memory longer than needed, a partial/corrupt range creates a false negative, or a stale/untrusted corpus is presented as authoritative | The experimental Kotlin/JVM matcher accepts a dedicated CharArray, clears it on every exit path, clears intermediate byte arrays, performs no network request, and persists no raw password. It opens the selected range with symbolic-link following disabled, captures the opened handle's size, reads no more than that many bytes, and rejects overlong records before decoding. It validates the full bounded range file before returning a match/no-match and treats missing, empty, malformed, oversized, truncated, symbolic-link or unsorted data as unavailable. The caller-supplied snapshot date and dataset provenance are not authenticated; concurrent in-place modification is not cryptographically detected; no-match applies only to the supplied range snapshot. This is password-only, not email/account breach lookup. |


## Offline password corpus inventory

- **Threats:** missing or substituted prefix files, unexpected files, symbolic links, malformed/unsorted suffix records, oversized ranges, post-import file changes, and a replaced manifest.
- **Current mitigation on PR #26:** the Go verifier requires the complete 1,048,576-file inventory, validates bounded records, hashes each range, writes/verifies an unsigned JSONL manifest, and verifies the directory against the manifest plus an independently retained SHA-256. A separate P-256 local attestation binds the manifest digest to a key whose fingerprint is supplied independently. The `verify-pwned-bundle` command checks that signature and then validates the full manifest and every range file against it. Kotlin validates the full ordered manifest and aggregate totals, then verifies only the selected range during an Android password lookup. A verified empty range can produce only a snapshot-scoped no-match.
- **Residual risk:** the manifest is unsigned. If the manifest and its expected digest are both replaced, the verifier cannot authenticate the inventory. It cannot prove HIBP publisher identity, remote completeness, or freshness; a syntactically valid truncated range can be included. The snapshot date is an operator claim. Android checks only the selected range's bytes during a lookup. The SAF adapter does not prove a provider is local or honest; the provider may fetch remote content, revoke access, or change its source between separate opens. The copied snapshot is bounded and digest-checked, but the experimental UI and one-shot SAF flow are present on PR #26; persistent-grant lifecycle and physical-device/provider validation remain outstanding.
- **Required next control:** validate the Android Keystore alias lifecycle on physical devices, including key persistence, missing/unusable alias behavior, app-data clear/reinstall, and fingerprint continuity. The current signature remains a local-key statement, not an HIBP publisher signature or proof that the app performed a check.


### Android password-entry and document-provider boundary

The experimental check screen does not save the password field in view state or expose it to Android autofill; it clears the editor before processing and when the screen pauses. It copies characters directly into a dedicated CharArray, which the matcher clears. This cannot prove that an IME/keyboard or Android editor has erased every internal buffer. A selected DocumentsProvider can be cloud-backed and observe which manifest/range documents are read, although PrivaCage passes it no password and performs no upload. The Activity interrupts its worker and cancels the per-check Android CancellationSignal on explicit cancellation or loss of foreground focus. The signal is passed to provider metadata queries and asset-open requests, allowing providers that honor it to stop their own work. A provider that ignores the signal or an already-blocked client-side read may still delay completion and cache cleanup. A successful no-match remains limited to the exact supplied snapshot.
