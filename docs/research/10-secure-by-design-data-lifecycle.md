# 10 — PrivaCage's Own Privacy and Security Architecture

**Research status:** design control baseline, 25 October 2026  
**Decision this note supports:** prevent the privacy auditor from becoming another rich telemetry collector.

## 1. First-party threat model

PrivaCage can become a high-value dataset even if it has no ad SDK. Its local database may reveal installed apps, contacted services, locations inferred from destinations, account-provider usage, app schedules, legal concerns and potential abuse situations. A cloud sync service, crash reporter, analytics SDK, support upload or debug log can accidentally centralize that history.

The project should treat data minimization as a core security control. NIST's Privacy Framework provides a voluntary risk-management approach for identifying and reducing privacy risk ([S25](SOURCES.md#s25)); OWASP MASVS organizes mobile security requirements around storage, cryptography, authentication, network communication, platform interaction, code resilience and privacy ([S26](SOURCES.md#s26)). Use these as checklists, not as a claim that following them alone certifies the application.

## 2. Data inventory and default policy

| Data | Default storage | Default retention | Export/cloud policy |
|---|---|---|---|
| Network flow metadata | Local encrypted/permission-protected database where feasible | Short rolling retention, user-configurable within safe bounds | Never sync by default; export only after preview |
| Raw packets/payloads | Do not store | None | Prohibited by default |
| DNS hostname history | Local only | Android: 7-day default, configurable to 24 hours or 30 days; at most 100 events; pruned on next app use | Export requires clear warning |
| App inventory/scan results | Local | Until user clears or replaces result | Do not transmit to fetch a label unless user opts in |
| APK file | Temporary workspace | Delete after scan by default | Never upload as a default side effect |
| Permission/consent history | Local | User-controlled; explain any append-only/tamper-evident behavior | Optional export |
| Legal requests and receipts | Local encrypted storage | Keep while useful; user can delete | No third-party relay by default |
| Crash diagnostics | Local minimal diagnostic state | Bounded | Opt-in export with redaction |
| Community tracker DB | Public, versioned data | Versioned history | No user traffic needed to update it |

For Android DNS hostname history, the policy is implemented: 7-day default with 24-hour, 7-day, and 30-day choices; at most 100 events and a 256 KiB serialized UTF-8 cap; and pruning on app launch, recording, history refresh, or export. There is deliberately no background worker whose only purpose is deleting history, so expired rows are removed the next time the app is used. If any stored timestamp is malformed, the whole prune operation stops and preserves the saved list rather than partially deleting evidence. Other data categories still need their own explicit periods. “Stored locally” is not enough: a shared device, malware, cloud backup or exported file can change the exposure model. State where the OS backs up the database and exclude sensitive logs from backups when the platform and threat model support doing so.

## 3. Data minimization in event design

- Never store contents of clipboard items, contacts, messages, request bodies, authentication headers, URL query strings or precise GPS by default.
- Do not replace sensitive values with ordinary unsalted hashes and call them anonymous. A hash of a low-entropy value can be guessed offline.
- Store categories and coarse indicators instead of data values: for example, `clipboard_access_signal_observed=true` only if a real sensor/API source produced it, not the clipboard text itself.
- Separate identifiers by purpose. Use local random record IDs, avoid cross-module linkage unless required, and rotate/purge summaries when the user resets history.
- Add maximum record sizes and bounded queues to prevent resource exhaustion from a noisy app.
- Keep logs from containing secrets in exception messages. Redact before serialization, not only in the UI.
- Do not retain full HTTP/DNS payloads for future debugging.

## 4. Local storage and cryptography

Use platform-backed key storage where available and vetted encryption APIs. Do not invent a cryptographic scheme. Document database encryption coverage, key protection, migration behavior and what remains available after device unlock. On Android, evaluate platform Keystore/StrongBox where applicable; on iOS, use Keychain/Data Protection appropriately. A key stored beside ciphertext without effective OS protection is not meaningful encryption.

Threat-model file exports too: signed logs may be tamper-evident but can reveal a user's network activity to anyone who receives them. Signing proves that a signature corresponds to a key; it does not independently prove that the underlying event was a complete/correct observation. Include metadata describing source, version, event coverage and known gaps.

## 5. Optional backend and sync

The safest v1 is no backend for personal activity. If sync is later added, require an explicit opt-in per data category, use end-to-end encryption with independently reviewed key management, minimize server metadata, make deletion/export easy, and verify that diagnostics cannot accidentally ship the encryption keys or decrypted data. “E2E encrypted” needs a concrete protocol, key recovery model, device enrollment and threat analysis; it cannot be a label attached to a generic HTTPS API.

A relay for legal requests is especially sensitive: it may receive legal identity information and request content. Prefer direct sending or user-mediated forms. If a relay is unavoidable, explain who operates it, what it can read, rate-limit/abuse protections, retention, transport/storage security, and how users can bypass it.

## 6. Supply chain and updates

- Pin and review dependencies; inventory SDKs and their own data collection.
- Build the public tracker database through a reproducible, reviewed pipeline.
- Sign database releases or otherwise authenticate update provenance; verify signatures before applying updates.
- Use monotonic versioning and anti-rollback checks for maliciously downgraded rulesets where feasible.
- Make updates auditable: show additions/removals/reclassifications and link sources.
- Never let a remote signature update silently make a destructive broad block rule effective without policy and user-visible safeguards.
- Test update parser inputs as untrusted data: limits, schema validation, unknown fields, URL schemes, regex catastrophes and malformed encodings.

## 7. Abuse-resistant logging

The normal and verbose renderers should be projections of the same structured event. The verbosity switch changes presentation, not evidence collection. Verbose mode must not turn on payload capture or store more sensitive fields. Use pagination/retention to control volume. The event store should have schema versioning, migrations, checksums or tamper-evident chaining where justified, and an explicit outcome for storage exhaustion.

An append-only ledger is useful only if deletion semantics are honest. If the user clears logs, the system should not claim permanent immutability. A local audit trail is evidence of events that the app recorded, not legally conclusive proof of everything another app did.

## 8. Security and privacy test gates

- Inspect outbound network traffic from a fresh install and from every settings/sync/diagnostics screen.
- Verify that disabling optional network features really stops their traffic.
- Search logs, crash files, exports, backups and analytics for seeded test secrets and identifiers.
- Fuzz event parsers, APK parsers and database-update files.
- Test lock/unlock, reboot, restore, key invalidation and database migration.
- Test device compromise/shared-device scenarios and user-initiated log deletion.
- Run dependency scanning, code review and independent security assessment before a stable release.
- Publish a clear security contact and vulnerability disclosure process.

## 9. Acceptance criteria

- Fresh install emits no personal telemetry or analytics events.
- No raw payloads/clipboard contents/credentials/exact coordinates appear in default logs.
- Every outbound network call has a documented purpose and a user-visible setting if optional.
- Log export previews sensitive scope and requires explicit action.
- Data retention and clear/delete behavior is implemented and tested, not merely described in the privacy policy.
- The project can prove which tracker/signature DB version was applied and reject invalid updates.