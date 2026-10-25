# 13 — Verification and Acceptance Test Plan

**Research status:** proposed test matrix, 25 October 2026  
**Goal:** make every shipped privacy claim falsifiable and repeatable.

## 1. Test layers

1. **Unit tests:** parsers, normalizers, rule precedence, deadline arithmetic, signature matchers, redaction, metadata scrub routines.
2. **Integration tests:** Android VPN routing, UID attribution, local persistence, app settings handoff, request status workflows, share-sheet outputs.
3. **Device matrix:** Android API/OEM versions, IPv4/IPv6, Wi-Fi/cellular, VPN conflicts, app lifecycle/reboot; iOS versions and entitlement-specific Network Extension prototypes.
4. **Privacy tests:** outbound traffic capture, seeded-secret search across logs/exports/backups, data deletion/retention behavior.
5. **Abuse/negative tests:** spoofed or stale signatures, malformed APKs, DNS bypass, shared CDN, unknown attribution, coercive-device scenario, wrong legal endpoint.
6. **Release verification:** reproducible build where feasible, signed tracker release, dependency inventory, known-issues list, reviewed UI copy.

## 2. Android VPN matrix

| Scenario | Expected result | Failure signal |
|---|---|---|
| Matching DNS query through tunnel and block rule | Query is handled according to rule; event records exact rule ID | UI says blocked without a drop/result record |
| Unknown hostname | Observe-only or configured default; no malicious conclusion | Unknown equals malicious |
| DoH/DoT or hard-coded IP bypasses hostname matching | Hostname unavailable or rule coverage limitation shown | App claims full domain coverage |
| TCP flow attribution available | UID mapped with method and confidence | UID guessed from foreground app |
| `getConnectionOwnerUid` returns invalid UID | Flow stays unattributed | Invalid UID silently becomes a package |
| IPv6 flow | Same declared policy applies if IPv6 is enabled | IPv6 bypasses IPv4-only rules unnoticed |
| VPN revoked/process killed | Status becomes inactive; filtering claim stops | Dashboard continues “protected” |
| Another VPN/system policy conflicts | Conflict/unsupported state shown | Silent route change or false success |
| Shared CDN/IP | IP-only evidence and shared-hosting caveat | All traffic to IP labelled one app's tracker |

Use a controlled test server under project control and non-sensitive fixtures. Never use real user traffic to validate payload inspection.

## 3. APK scanner matrix

- Valid small APK with a known test signature.
- APK with manifest permission but no related runtime use; output says requested/capable, not observed.
- APK with matching SDK class but no test execution; output says static indicator.
- Known tracker SDK version outside signature coverage; no false “none exist” promise.
- Obfuscated package and native library; limitations visible.
- Malformed manifest, zip bomb, path traversal entry, duplicate ZIP entries and oversized file; fails safely under resource limits.
- Two APK versions produce separate hashes and database versions.
- Signature removed/reclassified in DB; old reports still indicate which DB version produced them.
- User cancels scan; temporary APK is deleted according to policy.

## 4. Permissions/AppOps matrix

- Permission already granted; state accurately shown.
- User opens system Settings but makes no change; status does not report success.
- User revokes permission and returns; state re-read and verified.
- Permission group differs by Android version; label uses current platform meaning.
- App cannot query a package due to visibility; show unavailable, not not-installed.
- Root extension is absent; privileged-only operation is unavailable and no UI mock shows it as done.
- Root extension attempts unsupported operation; failure and partial state are visible; rollback behavior is tested.

## 5. Metadata scrub matrix

Fixtures should include GPS, make/model, timestamps, creator/author, software, XMP/IPTC, embedded thumbnails, orientation and color profile for each supported image/document format. Test clean and partial-failure paths. Re-parse output and compare display rendering where metadata removal could affect image orientation/color. Confirm original file hash remains unchanged and output is separate. Test malformed/encrypted/huge files and low disk space.

An output is “verified cleaned” only for the specific field categories and format validated by the parser. If a format embeds metadata in a container the implementation does not inspect, report unsupported/partial rather than success.

## 6. Legal rights workflow matrix

- GDPR/UK GDPR one-calendar-month calculation, including short months.
- Extensions only when recorded from a response and updated with reason/source.
- CCPA initial 45 calendar days and extension to 90 only under the current applicable requirements and notice.
- Jurisdiction mismatch prompts the user to review before sending.
- User edits or removes sensitive identity fields; preview reflects final request.
- Opening a form is not tracked as submission; user confirms submission separately.
- Email send failure does not change status to submitted.
- Duplicate sends are prevented or clearly confirmed.
- Response says data retained under an exception; UI records response without automatically judging legality.
- California DROP flow uses official user-facing mechanism; no private/undocumented API calls occur.
- User clears request history; local receipts and cached text are actually removed per documented policy.

## 7. Privacy regression tests

Create seeded secrets (fake emails, unique strings, mock coordinates and dummy tokens) and search for them in:

- log database;
- crash reports and stack traces;
- exported JSON/CSV/PDF;
- temporary files and cache;
- backup/restore output;
- outbound network payloads;
- analytics/diagnostic SDK traffic.

A “hash” of a secret is not automatically safe. Test whether low-entropy values can be recovered from logged hashes. Confirm no raw packet payload, clipboard text or authentication header is stored by default.

## 8. Stalkerware/safety regression tests

- App does not auto-disable accessibility/admin services.
- A suspicious-looking legitimate assistive service is described neutrally.
- A scan result does not trigger a notification revealing the exact finding by default.
- User exits or discards a report without a new saved record or network transfer.
- “No findings” does not imply the device is safe.
- User can read coverage limitations and specialist safety guidance without forced automatic actions.

## 9. Acceptance rule

Every privacy claim in UI copy must map to at least one automated test, a manual verification procedure or an official API/source statement. If it cannot be verified, rephrase it as a limitation or remove it from the shipping UI. Attach test environment, OS version, tool version and result to release evidence.