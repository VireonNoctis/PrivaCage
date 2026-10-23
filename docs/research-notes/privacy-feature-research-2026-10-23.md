# Privacy feature research — 23 October 2026

This note records candidate features grounded in official platform documentation and security guidance. These are research findings and implementation candidates, not claims that PrivaCage already provides these protections.

## Findings and candidates

### 1. Selected-file metadata inspector and scrubber — high priority, locally buildable

Android's Photo Picker grants access to user-selected media rather than requiring broad access to the entire library. Android's EXIF documentation recommends AndroidX ExifInterface over the platform class because it is more updateable and supports additional metadata and image formats. The same reference documents that saving attributes rewrites the underlying image and warns of a DNG-related data-corruption issue on some Android 13 devices.

Implementation shape:
- Add an explicit “Inspect before sharing” file-picker entry point; use selected URI grants, not broad media-library permission.
- Read metadata locally and present a before/after field diff for GPS coordinates, timestamps, camera/device identifiers, author/software fields, and thumbnails where supported.
- Write a sanitized copy to a separate output URI. Never rewrite the user's selected original.
- Re-open and inspect the output before saying that recognized fields were removed. Report unsupported formats and unparsed metadata as uncertainty.
- Add fixture images with GPS, orientation, thumbnails, XMP/IPTC, and malformed metadata; test the sanitized output rather than only asserting that a helper was called.

Grounding:
- Android Photo Picker: https://developer.android.com/training/data-storage/shared/photo-picker
- Android EXIF API and AndroidX recommendation: https://developer.android.com/reference/android/media/ExifInterface

Limit: stripping recognized metadata cannot hide landmarks or other identifying content visible in the pixels. EXIF scrubbing is not a complete anonymizer for PDFs, Office files, videos, or every proprietary image format.

Suggested integration: new platform-neutral metadata report model plus Android file-processing adapter; local event type `metadata.inspect.completed` and `metadata.scrub.completed`. Add a “Share safely” UI and retain an untouched original.

### 2. Protected local settings and export lifecycle — high priority

OWASP's mobile security guidance says sensitive local data should be encrypted and that Android Keystore / Apple's Keychain or Secure Enclave should be used for device-held secrets. PrivaCage currently keeps DNS rules in local preferences and supports a separate passphrase-encrypted export. These have different jobs: the export passphrase supports transfer; device-bound keys can protect at-rest records without storing that passphrase.

Implementation shape:
- Inventory every persisted field and decide whether it is sensitive, redundant, or safe to store unencrypted.
- For Android, use a Keystore-backed data-encryption key where supported; never persist the raw key beside ciphertext. Design a versioned migration with atomic writes, crash recovery, and an explicit fallback when a key becomes unavailable.
- Define iOS storage via Keychain and platform-specific access controls rather than assuming the Android storage model maps directly.
- Exclude secrets from debug backups and logs; test backup/restore and locked-device behavior. Do not silently reset user rules when decryption fails.

Grounding:
- OWASP Mobile Application Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html
- OWASP Key Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html

Limit: device-bound at-rest encryption is not a cross-device sync protocol and does not protect data from a compromised unlocked device or malicious app build.

Suggested integration: local storage module, encrypted record envelope, migration journal, and local audit events `storage.migration.started/completed/failed`. UI should show recoverable vs unrecoverable storage errors without exposing secrets.

### 3. VPN preflight, state visibility, and DNS route diagnostics — high priority

Android VpnService is user-controlled and can conflict with the VPN another app is currently using. Google Play's VpnService policy requires a Play listing disclosure and prominent in-app disclosure plus affirmative consent where sensitive data is accessed or collected. It also prohibits using the service to collect personal/sensitive data without that consent.

Implementation shape:
- Before enablement, explain the DNS data that is inspected, what is logged, and what is never collected; explicitly warn that starting this VPN may replace another VPN.
- Surface the real service/tunnel lifecycle state (requested, consent required, starting, active, stopping, error), derived from the service rather than a stored button state.
- Add a local diagnostic that checks the configured resolver path and records rule decisions and transport failures without retaining query payloads.
- Test VPN revocation, Wi-Fi-to-mobile handover, captive portal, resolver timeout, app process death, and stop/restart.
- Phrase diagnostics as evidence about tested paths, not a proof that every app, IPv6 route, or encrypted-DNS resolver is covered.

Grounding:
- Android VPN guide: https://developer.android.com/develop/connectivity/vpn
- Android VpnService reference: https://developer.android.com/reference/android/net/VpnService
- Google Play VpnService policy: https://support.google.com/googleplay/android-developer/answer/12564964

Suggested integration: service-state repository and local diagnostic report; event types `vpn.state.changed`, `dns.query.blocked`, `dns.upstream.failed`, and `dns.diagnostic.completed`. Store counts and decisions by default, not raw DNS names.

### 4. iOS privacy filter based on approved NetworkExtension capabilities — medium priority, entitlement-gated

Apple documents separate NetworkExtension entitlement values for DNS proxying, content filtering, app proxy, and packet tunnelling. Its content-filter architecture separates the filter data provider that inspects traffic from the control provider that manages configuration, with sandboxing intended to constrain exfiltration from the data provider. The documented capabilities and distribution constraints differ; they should not be represented as one generic “iOS VPN API”.

Grounding:
- Network Extension entitlements: https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.networking.networkextension
- Content filter providers: https://developer.apple.com/documentation/NetworkExtension/content-filter-providers
- NetworkExtension overview: https://developer.apple.com/documentation/NetworkExtension

Implementation shape: first create an entitlement/distribution feasibility checklist and a tiny signed proof-of-concept for the exact intended distribution path. Keep local filtering data separate from the control UI. If entitlement or deployment access is unavailable, ship a clearly labeled companion surface that links to native privacy settings instead of a fake filter.

### 5. App-update privacy diff — high priority, local processing

A user-selected APK can be compared with another user-selected APK for manifest permission changes, exported components, SDK signature matches, and embedded endpoint candidates. The output should be a reproducible diff whose source APK hashes and scanner/signature versions are recorded.

Implementation shape:
- Add a parser result schema with evidence origin and confidence.
- Keep original APK files user-selected and local by default.
- Fuzz binary/manifest parsers and impose file-size, entry-count, and decompression-ratio limits.
- Mark a permission or library as static evidence, never proof that a runtime action occurred.
- Show added/removed findings and their source evidence rather than a simplistic private/not-private score.

Suggested integration: APK scanner, signature database, and UI comparison view; events `apk.scan.completed` and `apk.diff.completed`. No upload of binaries or app inventories.

### 6. Minimal, redacted audit export — high priority

Privacy tools can create new privacy exposure through their own reports. Exports should include only selected date ranges and event categories, preview redactions before writing, strip internal file paths/device identifiers where possible, and offer retention controls. Logs should distinguish observed network destinations from inferred app attribution and should not default to storing query names or payloads.

Grounding: OWASP mobile security guidance specifically warns about leakage through caches, logs, and background snapshots: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

Suggested integration: a typed event store, deterministic redaction rules, and export preview. Test both positive redaction and preservation of required audit fields. Rare combinations can still identify a person; disclose that residual risk.

### 7. Privacy-preserving data-broker request assistant — medium priority, research/legal review required

The FTC's January 2024 action involving X-Mode Social/Outlogic illustrates that location histories can reveal highly sensitive visits and that broker handling of location data is a concrete consumer privacy concern.

Implementation shape:
- Maintain a sourced registry of companies, verified opt-out routes, last-checked dates, and jurisdiction-specific requirements.
- Draft user-reviewed requests and save submission evidence separately from company confirmation.
- Prefer self-service browser flows and user-controlled submission over sending identity documents to an unverified relay.
- Keep data-broker opt-outs separate from GDPR/CCPA deletion request templates; do not claim one request covers downstream recipients or copies.

Grounding: https://www.ftc.gov/news-events/news/press-releases/2024/01/ftc-order-prohibits-x-mode-social-and-outlogic-selling-sensitive-location-data

Limit: a request submission is not proof of deletion or removal from resellers. Legal templates require renewed jurisdiction/date review before shipping.

### 8. Offline breach-exposure lookup — research before integration

A locally downloaded and documented dataset can support private lookup without submitting a raw email address to a third-party API. Dataset coverage, update time, licensing, and false-negative risk must be visible. A remote k-anonymous query still discloses a prefix or bucket and must not be advertised as “no data leaves the device”.

Suggested integration: signed dataset manifest, local indexed lookup, and user-entered identifier held only for the session; event `exposure.lookup.completed` should store neither the identifier nor its unsalted hash. The dataset source and licensing need review before selecting one.

### 9. Coercive-monitoring safety signals — research before implementation

Unexpected device-admin status, accessibility access, or persistence can justify a review prompt only when surfaced through supported APIs. None is proof of stalkerware. Automatic removal, a conspicuous alert, or a network change could increase risk if an abusive person monitors the device.

Suggested integration: opt-in local safety checklist, quiet-by-default guidance, and a report that labels every signal and limitation. A safe implementation requires specialist safety review and must not promise definitive spyware detection.

### 10. IoT inventory and outbound baseline — later-stage, network-dependent

A handset's VPN cannot observe all traffic generated by other devices on the same LAN. A useful inventory therefore needs explicit local-network permission or router/user-controlled resolver data, plus conservative vendor attribution. It must avoid scanning networks without authorization.

Suggested integration: local device inventory and user-confirmed scan; event types `lan.scan.started/completed` and `device.destination.changed`. Label MAC/vendor inference as uncertain and do not send device inventories to a server by default.

## Priority order

1. Fix and verify the existing encrypted-profile interoperability before adding an E2EE sync service.
2. Add the selected-file metadata inspector/scrubber and its round-trip tests.
3. Make VPN state, preflight disclosure, and network handover behavior observable and testable.
4. Protect sensitive persisted settings and add migration/backup tests.
5. Add local APK privacy diffs and redacted audit export.
6. Prototype iOS NetworkExtension only after confirming the intended entitlement and distribution route.
7. Treat broker workflows, breach datasets, stalkerware signals, and IoT scanning as separate research-gated features.

No candidate above should be presented as implemented until its actual data source, platform limits, tests, and user-visible failure states are in place.


### 11. Encrypted upstream DNS with authenticated resolver identity — high priority, requires a deliberate transport design

Android's security guidance warns that a custom DNS transport can bypass the platform's Private DNS protections. DNS over TLS encrypts the client-to-resolver path, but strict mode must authenticate the resolver hostname; opportunistic encryption can fall back to plaintext and should not be described as equivalent protection. PrivaCage's current upstream forwarder uses plain UDP and TCP to a configured IPv4 address, so the local filtering path does not itself encrypt queries between the device and resolver.

Grounding:
- Android guidance on insecure DNS transport: https://developer.android.com/privacy-and-security/risks/bad-dns
- DNS-over-TLS strict vs opportunistic profiles: https://developers.google.com/speed/public-dns/docs/dns-over-tls

Implementation shape:
- Add an explicit resolver profile with both a hostname for certificate validation and a transport choice; do not infer a TLS identity from an IPv4 address.
- Prefer strict TLS with normal platform certificate verification and a documented hostname. A failed secure connection should fail closed unless the user explicitly chooses a separately labeled fallback.
- Keep local domain policy evaluation before forwarding and avoid recording raw query names.
- Test invalid certificates, hostname mismatch, TLS negotiation failure, resolver timeouts, network handover, and any configured fallback.
- Explain that the resolver can still observe the queries and source IP; transport encryption hides DNS content from local-network observers, not from the resolver itself.

Suggested integration: a resolver transport interface in the DNS core and an Android TLS-backed adapter, with local event types `dns.transport.secure`, `dns.transport.failed`, and `dns.transport.fallback`. Do not advertise this as implemented until certificate validation and real-device tests pass.

### 12. Backup and restore privacy audit — high priority, mostly static checks plus device tests

Android Auto Backup can include app preferences and internal files by default. PrivaCage's current manifest sets `android:allowBackup="false"`, which is a useful explicit baseline; Android's guidance also warns that backup and device-to-device transfer behavior can vary by OS version and manufacturer. The app should not rely on a single manifest flag as proof that every OEM transfer path is disabled.

Grounding:
- Android Auto Backup behavior and configuration: https://developer.android.com/identity/data/autobackup
- Android backup security recommendations: https://developer.android.com/privacy-and-security/risks/backup-best-practices
- OWASP test for sensitive data excluded from backups: https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/

Implementation shape:
- Add a CI static check that confirms the manifest explicitly declares its backup posture and flags changes for review.
- Document the intended tradeoff: sensitive local rules are not silently restored; users can export them using the authenticated `.pcage` format.
- Add emulator/OEM test steps for cloud restore and device-to-device migration before claiming backup exclusion is comprehensive.
- Keep backup checks as evidence of configuration, not a guarantee about every device's vendor-specific transfer behavior.

Suggested integration: a manifest policy check in the existing Python validation workflow and a manual device-test checklist. No extra permissions or data collection are needed.

### 13. Signed tracker-catalog releases and anti-rollback — required before remote catalog updates

The current catalog is bundled with the app and validated for schema and URL structure. That protects against malformed data, but schema validation cannot authenticate who published a file. If PrivaCage later downloads catalog updates, a compromised repository token or release pipeline could publish malicious entries, remove protective entries, or serve an older catalog.

Implementation shape:
- Evaluate an established update framework such as The Update Framework (TUF) rather than designing a custom signed-JSON protocol.
- Authenticate catalog metadata with pinned trust roots, versioned metadata, expiry checks, key rotation, and rollback/freeze protections appropriate to the chosen framework.
- Keep catalog release version, source revision, and content hash visible in the app and log which version informed a match.
- Test invalid signatures, expired metadata, older-but-valid metadata, key rotation, missing files, and interrupted updates.
- Preserve a last-known-good catalog and do not silently replace it with an invalid or older release.

Grounding:
- TUF specification: https://theupdateframework.io/specification/latest/

Limit: signatures prove publication under an accepted key, not that each indicator is correct. Human evidence review and conservative status assignment remain necessary. There is no remote catalog updater to protect yet.

Suggested integration: signed metadata alongside `shared/tracker-db/signatures.json`, updater verification before catalog activation, and events `tracker.catalog.verified`, `tracker.catalog.rejected`, and `tracker.catalog.rollback_blocked`.

### 14. Cross-device encrypted sync threat model — design gate before a backend

The PCAGE01 envelope supports passphrase-based file transfer, not device identity or synchronization. A server-side encrypted blob by itself does not define who may read or replace a profile, how devices join or leave, or what happens when a device is lost.

Implementation shape:
- Write and review a threat model before choosing backend endpoints or building account screens.
- Specify authenticated device enrollment, key derivation and rotation, device revocation, encrypted conflict metadata, replay handling, version rollback protection, account recovery, and what metadata the server can observe.
- Keep client-side encryption and decryption as the trust boundary; the relay should not receive the passphrase or plaintext profile.
- Use a reviewed protocol/library for key establishment and message authentication rather than creating novel cryptographic primitives.
- Test wrong-device, revoked-device, stale-version, duplicate-upload, corrupted-blob, lost-key, and restore scenarios.

Grounding:
- OWASP Key Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- OWASP Mobile Application Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

Limit: this is a design candidate, not implemented sync. End-to-end encryption does not hide all metadata, prevent endpoint compromise, or solve recovery and revocation automatically.

Suggested integration: a separate opt-in sync module and backend relay only after the protocol review; no sync should be advertised until independent tests verify that the server cannot decrypt stored profile contents.

### 15. Tamper-evident audit checkpoints — local-first, useful with clear limits

A local event log is useful for reconstructing decisions, but a database described as append-only can still be edited by code with filesystem access or by a user/device with sufficient control. A hash chain can make accidental or partial edits detectable relative to a trusted checkpoint; a chain stored entirely beside the log is not proof against an attacker who can rewrite both.

Implementation shape:
- Canonicalize and sequence structured event records before hashing; exclude secrets, raw DNS question names, and packet payloads by default.
- Periodically sign or export a checkpoint using a key protected separately from the event database where the OS supports that separation.
- Verify chain continuity on open and export; report which range failed instead of silently repairing or dropping events.
- Allow user-initiated signed export and document that timestamping is local-clock time unless backed by an independent timestamp service.
- Test deleted, reordered, modified, duplicated, and truncated events plus unavailable signing keys.

Grounding:
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Mobile Application Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

Limit: a local hash chain is not a trustworthy external timestamp, and cannot prove that unobserved events never happened. It is tamper evidence only when the checkpoint trust anchor remains outside the attacker's control.

Suggested integration: structured local event storage and user-controlled signed export; event types `audit.checkpoint.created`, `audit.chain.verified`, and `audit.chain.verification_failed`. Avoid converting this into a telemetry upload feature.

