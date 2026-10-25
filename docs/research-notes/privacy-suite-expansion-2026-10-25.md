# PrivaCage Privacy Suite Expansion — Research and Engineering Notes

**Review date:** 25 October 2026  
**Branch:** `feat/privacy-suite-expansion-2026-10-25`  
**Scope:** tracker intelligence, Android DNS policy/packet path, permission auditing, APK analysis, encrypted profiles, alternative-app selection, Windows privacy controls.

This note records the implementation decisions and the boundaries which must remain visible in UI and documentation. A static indicator is not runtime proof. A configured policy is not proof of effective enforcement. Tests of a pure packet codec are not a substitute for operating-system or device validation.

## 1. Executive assessment

PrivaCage is best described as a local-first privacy auditing and selected-policy enforcement toolkit, not a universal tracker detector or a one-switch anonymity product.

The current codebase has several different maturity levels:

| Capability | Current evidence | Remaining validation |
|---|---|---|
| Shared tracker intelligence | Versioned JSON schema, HTTPS evidence URLs, confidence/status/review fields, Go validation/report tools | More independent reviewers, feed provenance/signature governance, adversarial/duplicate feed tests, wider record coverage |
| Android DNS policy | Pure Kotlin evaluator and IPv4/IPv6 UDP-DNS packet processing, bounded upstream transports, blocked response generation | Emulator and physical-device route, lifecycle, resolver, IPv6, transition and OEM tests |
| Android tracker list | Bundled canonical catalogue, evidence and status rendered locally, explicit import of active domains into the rule editor | Improve search/filtering and test the full UI manually; import still requires explicit save |
| APK static audit | Local file staging, bounded size, SHA-256, manifest metadata, permission and exported-component report, `apksig` verification, bounded DEX-string scan | Fuzz malformed archives, run corpora across SDK levels, validate decompression/resource limits and report UX |
| Permission audit | Launcher-visible dangerous-permission declaration/grant scan and local before/after baseline diff | Audit package-visibility behavior across OS/OEM versions; user test for baseline resets and incomplete scans |
| Encrypted profile transfer | PCAGE01 Argon2id/AES-256-GCM format, Android export/import through Storage Access Framework, shared Kotlin/Rust known-answer vector | End-to-end device interoperability and recovery UX; file format does not authenticate sender identity |
| Google-suite alternatives | Bundled catalogue, allowlisted HTTPS URLs, source picker and locally persisted sequential install queue | App-by-app source re-review; official store/source performs download and install; not a silent/direct APK downloader |
| Windows privacy controls | Read-only local audit, documented allowlisted policy changes, UAC/confirmation, protected backup, post-write verification and restore | Test on representative Windows builds/editions and managed devices; effective policy can be overridden by domain/MDM and network policy has disruptive failure modes |
| Web console | Svelte client with Rust API for tracker intelligence | Device pairing/event ingestion is not yet a connected live-monitor pipeline |
| iOS | Design and platform notes | NetworkExtension entitlement/distribution constraints must be resolved before promising broad monitoring |

## 2. DNS policy and packet engine

### 2.1 Scope of the routing design

Android's `VpnService.Builder.addRoute` supports IPv4 and IPv6 routes. PrivaCage deliberately routes two virtual DNS destinations rather than all IP space: an IPv4 virtual resolver and an IPv6 virtual resolver. The packet engine handles classic DNS over UDP addressed to those endpoints. It does not claim to be a full-device packet firewall.

Useful platform references:

- [Android `VpnService`](https://developer.android.com/reference/android/net/VpnService) — service lifecycle, user authorization and the VPN contract.
- [Android `VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder) — addresses, DNS servers and route construction for IPv4/IPv6.
- [Android VPN guide](https://developer.android.com/develop/connectivity/vpn) — VPN service setup and the platform-level behavior.
- [RFC 6891 §6.1.2](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.2) — EDNS(0) OPT record fields.
- [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html) — DNS-over-TCP requirements for general DNS implementations.

Upstream sockets must be protected through Android's VPN API so the resolver requests do not route back into the same tunnel. VPN consent, route behavior, revocation and foreground-service lifecycle are OS-controlled states and require integration tests. A unit test that injects one packet into a Kotlin engine cannot confirm the route seen by other applications.

### 2.2 Validation policy

The packet processor now dispatches based on IP version and has separate IPv4 and IPv6 UDP-DNS codecs. IPv6 parsing is intentionally strict:

- Validate the fixed 40-byte header, the exact declared IPv6 payload length, UDP length and checksum.
- Reject IPv6 extension headers, fragments and jumbograms; do not treat an extension header as UDP.
- Reject non-DNS UDP destinations and unsupported protocol shapes.
- Build responses with swapped endpoints and a valid IPv6 UDP pseudo-header checksum.
- Do not silently truncate response payloads that cannot fit the configured 1,500-byte TUN MTU.

These constraints keep the codec's promise narrow. Full IPv6 extension-header traversal, fragment reassembly, path-MTU discovery and a general IPv6 stack are not implemented.

### 2.3 Known DNS blind spots

Classic DNS blocking cannot reliably identify all tracking. An app can use:

- DNS-over-HTTPS, DNS-over-QUIC or a private resolver it controls;
- a literal IP address, cached address or hard-coded endpoint;
- another VPN or proxy layer;
- shared SDK infrastructure that also serves functional product features.

Android also has system resolver privacy features and modern encrypted-DNS behavior; a custom local DNS route does not prove every app's encrypted DNS path is intercepted. Read the [Android DNS and connectivity documentation](https://developer.android.com/develop/connectivity). Do not advertise a DNS-only VPN as a full traffic monitor, and do not recommend always-on lockdown until ordinary network traffic and recovery behavior are proven on target devices.

**Next DNS gate:** CI unit tests for IPv4/IPv6 codec behavior, then emulator smoke tests and physical-device checks for VPN consent, adding/removing each virtual route, DNS resolution under IPv4-only/IPv6-only/dual-stack networks, sleep/wake, Wi-Fi/mobile handover, captive portals, resolver timeouts, stopping/revocation, and no upstream socket loop. Keep packet/name retention disabled by default.

## 3. Tracker intelligence format

### 3.1 Schema and meaning

The canonical file is `shared/tracker-db/signatures.json`; its version-1 schema requires stable IDs, a component/service name, category, typed indicators, confidence, lifecycle status, `last_verified`, and evidence URLs. Unknown fields are rejected so misspelled policy data cannot be silently ignored. The Go tool in `shared/go/pcage-tools/` validates structure and can produce review-freshness reports.

Indicator semantics:

- **Domain** identifies a known endpoint/service. It does not identify the originating application and does not reveal the contents of a TLS session.
- **SDK class pattern** is evidence of a class-name/string reference in a static binary. Obfuscation, reflection, native code, minification, dead code and packaging can create false negatives or ambiguous matches.
- **Confidence** expresses confidence in the association between the indicator and the documented service, not probability that the scanned app exfiltrated personal data.
- **Active** permits explicit user review and import where supported. It is not a universal block recommendation. **Review** and **retired** entries must not be silently bulk-imported into blocking rules.

The catalog has been expanded with documented Android SDK indicators for Amplitude, Firebase Crashlytics, Branch, PostHog, Sentry, Mixpanel and OneSignal. These records use medium confidence: SDK presence does not prove initialization, configuration, event types, user identifiers, or transmission. Official documentation supports the stated SDK purpose, not the runtime behavior of any specific app.

References:

- [Amplitude Android Kotlin SDK](https://www.amplitude.com/docs/sdks/analytics/android/android-kotlin-sdk) documents event collection and configurable autocapture.
- [Firebase Crashlytics for Android](https://firebase.google.com/docs/crashlytics/android/get-started) documents crash, non-fatal-error and ANR reporting.
- [Branch Android integration](https://help.branch.io/developer-hub/android-basic-integration) documents SDK event and deep-link functionality.
- [PostHog Android SDK](https://posthog.com/docs/libraries/android) documents configurable analytics, event queues and session replay features.
- [Sentry Android SDK](https://docs.sentry.io/platforms/android/) documents mobile error monitoring and diagnostics.
- [Mixpanel's Android SDK](https://github.com/mixpanel/mixpanel-android) is its official Android analytics library.
- [OneSignal's Android SDK](https://github.com/OneSignal/OneSignal-Android-SDK) implements push/in-app engagement integration.

### 3.2 Quality requirements for future records

A useful tracker-intelligence pipeline should include more than increasing record count:

1. Require first-party technical evidence or a clearly identified authoritative source, date, and reviewer.
2. Keep an exact indicator type (domain versus class pattern) and a separate confidence/status field.
3. Reject unbounded wildcards, arbitrary string substrings, invalid hostnames, duplicate IDs, stale dates and unknown fields.
4. Store acquisition URL, retrieval time, upstream digest/license where appropriate, and an immutable catalogue version for reproducible reports.
5. Separate upstream feeds from manually maintained evidence-backed signatures. A hosts feed is useful for discovery but a bare list does not prove the service is a tracker.
6. Stage candidate updates as review records, compare diffs and require human approval before converting candidates to active enforcement.
7. Test false-positive-prone common domains, subdomain boundary matching, IDNA, malformed JSON and large input bounds.
8. Never equate a count of tracker records, SDK strings, or DNS matches to a quantified privacy risk score without a validated methodology.

Automated feed updates should be additive/review-only until source integrity, attribution and removal semantics are designed. Do not download arbitrary blocklists and immediately enforce them.

## 4. Android permission audit

The permission audit uses Android's package visibility model and scans launcher-visible applications. It reports dangerous permissions declared in manifests and the grant flags Android exposes. The new local comparison model distinguishes:

- newly declared dangerous permissions;
- dangerous permissions no longer declared;
- previously ungranted permissions now granted;
- previously granted permissions now ungranted;
- packages that entered or left the visible scan set.

It must not turn “package not visible anymore” into “permission revoked.” It also must not label a declared permission as live access or evidence that data was transmitted.

Android recommends requesting the smallest package-visibility scope necessary; `QUERY_ALL_PACKAGES` is not the default solution. See [Declare package visibility needs](https://developer.android.com/training/package-visibility/declaring). The audit intentionally stays within launcher-query visibility instead of attempting a complete inventory of all Google/Samsung services, hidden packages, work-profile apps, or privileged components.

The baseline lives in app-private preferences and can be cleared by the user. It stores package names, dangerous permission names and booleans, not content, location coordinates or network history. If any package could not be inspected in a scan, the baseline is not advanced, preventing an incomplete view from being mistaken for genuine permission removals.

Permission changes still need to happen through Android's own settings or documented APIs. PrivaCage does not silently revoke another app's ordinary user permissions and does not claim to observe live camera/microphone/sensor use from this permission list.

## 5. APK static audit

The current audit accepts a user-selected APK and performs analysis locally with a size cap. It extracts package/version/target-SDK information, declared permissions, exported component declarations, SHA-256, signer certificate fingerprints when available, signature-integrity results through Google's `apksig`, and a bounded scan of DEX strings against the tracker catalogue. The staged temporary file is removed after inspection; the APK is not installed or executed by the audit path.

Signature verification must be described precisely: a valid APK signature confirms signature integrity under the signing scheme, not publisher identity or trustworthiness. A class/domain string indicates a possible embedded component, not runtime use. Missing strings are not a clean bill of health.

Recommended hardening work:

- Add malformed ZIP/DEX/manifest corpora and property-based tests for archive size, entry count, decompressed-size and string-scan limits.
- Verify that corrupted signing blocks, absent/multiple signers, certificate rotation and malformed archives are reported as distinguishable outcomes.
- Keep extracted indicators explainable and source-linked; avoid a single unsupported “safe/unsafe” verdict.
- Re-test the maximum-size limit with compressed inputs, not only input file length.
- Keep all scanning offline and disclose that native code, reflection, encrypted resources and runtime downloads are outside static visibility.

## 6. Encrypted profile transfer and sync

The portable PCAGE01 profile format already uses Argon2id v1.3 with fixed reviewed resource parameters to derive a 256-bit key and AES-256-GCM with a fresh nonce and authenticated header. Android writes the encrypted envelope through the Storage Access Framework. Kotlin/JVM and Rust implementations share a known-answer fixture.

This is encrypted configuration transfer; it is not by itself authenticated sender transfer. Anyone who gets both the file and passphrase can decrypt it, and the receiver cannot infer sender identity from this envelope. The passphrase must be exchanged separately, and recovery exports should stay offline.

Separate E2EE sync protocol code uses device signing/encryption keys and trust-roster checks, but UI/relay integration, roster revision continuity, and actual device lifecycle still require full test passes. Keep these features conceptually separate:
- encrypted envelope confidentiality/integrity;
- authenticated sender/device identity;
- relay authorization and metadata exposure;
- recovery/key rotation and revocation.

Do not claim that end-to-end encryption conceals metadata from a relay, or that restoring a recovery bundle creates a new cryptographic device identity.

Format specification: [Encrypted profile envelope](../encrypted-profile-format.md). Sync protocol notes: [E2EE sync protocol](../e2ee-sync-protocol.md).

## 7. Google-suite privacy alternatives and install automation

The new `shared/app-alternatives/catalog.json` contains 29 curated alternatives across mail, cloud files, photos, maps, browsers, search, video, calendar, notes, keyboard, authenticator, contacts, app repositories, messaging, video calls, password management, news/RSS, translation and office documents. Each record separates:
- what it replaces and why it might help;
- known trade-offs;
- an evidence/privacy page;
- source options (official store or project distribution).

The Android screen validates schema fields and limits URLs to HTTPS on exact reviewed hostnames. Users can filter and select alternatives, choose the available source per item, persist the queue locally, and open one selected source at a time. Install completion is a user-maintained reminder; PrivaCage cannot infer successful installation just because the browser/store opened.

**Why this is not a silent APK sideloader:** catalogue entries currently point to curated store/project landing pages, not version-pinned APK binaries. An automatic direct downloader should only be introduced when each artifact has a reviewed release channel, exact version, SHA-256, expected signing-certificate identity or a verifiable repository index, redirect policy, and update/revocation process. Downloaded APK installation also has an Android system confirmation step. See [Android PackageInstaller](https://developer.android.com/reference/android/content/pm/PackageInstaller), where `STATUS_PENDING_USER_ACTION` explicitly requires the app to involve the user.

A proper future downloader would:
1. resolve a selected catalogue item to a signed/verified release index;
2. fetch only a version-pinned artifact over HTTPS with an explicit redirect and size policy;
3. verify its digest and signer before opening the package-installer flow;
4. explain source, version, signer fingerprint, and permissions before installation;
5. hand off installation to Android and wait for the system's result rather than claiming success;
6. keep store-managed apps in the store flow and never bypass Play Protect or installer consent.

That work is deliberately not faked in this change. The sequential source queue is real and useful today, but it is not a background artifact downloader. The catalog must be reviewed periodically because upstream apps, policies, releases and store listings change.

## 8. Windows privacy auditor and hardening

The Windows code already has two distinct tracks:

- **Read-only audit** collects a selected local baseline and labels findings by the evidence available. It is not a general packet monitor.
- **Policy hardening** uses a fixed allowlist, explicit confirmation, UAC elevation where required, protected rollback state, post-change verification and a restore path. Balanced/strict policies are separated from disruptive network isolation options. The repository also includes a pinned Win11Debloat submodule, which has its own options, behavior, and restore semantics.

Microsoft's current policy documentation says the “Diagnostic data off” value is supported only on Enterprise, Education and Server editions for the described Windows diagnostic-data setting; the common Pro setting selects Required diagnostic data instead. Additional diagnostic-log and dump controls are limited to Windows 11 and Windows Server 2022. Sources:

- [Microsoft System Policy CSP — AllowTelemetry](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system)
- [Configure Windows diagnostic data](https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization)
- [Microsoft Experience Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience)

A local policy registry value may not be the effective policy when MDM/domain policy overrides it. It controls documented operating-system behavior, not every third-party desktop app, service, driver, firmware component, hypervisor, hardware management engine, external router, or remote management plane. The emergency firewall isolation option can break DNS, internet, updates, remote administration and cloud services; require a separate explicit confirmation and a physical/local recovery plan.

Do not expand the current hardening allowlist by copying random “debloat” registry scripts. Each additional setting requires: official policy source, supported edition/build gate, previous-state capture, rollback test, post-write verification, failure injection, and an explanation of what may break. Preserve Defender, Windows Update, SmartScreen, licensing and certificate validation.

## 9. Required verification gates

Before a release claim is made, CI and maintainers should verify:

### Tracker intelligence
- `go -C shared/go/pcage-tools test ./...`
- `go -C shared/go/pcage-tools run . validate-tracker --max-age-days 180`
- `go -C shared/go/pcage-tools run . tracker-report --format markdown`
- malformed URL/date/domain/ID/status/indicator fixtures and duplicate IDs.

### Android
- `gradle :android-core:test`
- `gradle :app:testDebugUnitTest`
- `gradle assembleDebug`
- IPv4/IPv6 packet fixtures, invalid checksum/length, unsupported headers, response MTU cap, blocked and forwarded packet flow, alternative catalogue allowlist tests, permission diff tests.
- Emulator and physical-device VPN route/lifecycle checks; these cannot be inferred from JVM unit tests.

### Windows
- `go test ./...` from `windows/pcage-audit/` on both Windows and Linux CI where supported.
- Windows smoke tests for edition-gated policy preview, confirmation/elevation, backup ACL/state capture, verification, forced-failure rollback and successful restore.
- Never run disruptive network-isolation tests on shared CI agents without a disposable runner/recovery channel.

### Distribution and UX
- Validate that all app-alternative URLs are valid HTTPS links on the reviewed host allowlist.
- Check each catalogue item’s sources and trade-offs against current upstream docs before release.
- Confirm no unrequested network requests, telemetry SDKs, silent package installs or upload of local reports were introduced.
- Manually test VoiceOver/TalkBack labels and larger text, keyboard/focus order, long catalogue names and failed external-link handling.

## 10. Known limitations and next useful features

1. **Per-app DNS attribution (research/engineering required):** ordinary VPN APIs do not expose a portable, always-reliable mapping from every query to the originating application. Investigate only documented APIs and root-only approaches separately; do not infer it from destination IP.
2. **Signed tracker-feed ingestion (buildable with careful design):** download candidate data into a review channel, validate signatures and checksums, preserve feed license/provenance, produce reproducible diffs, and never auto-enforce a new feed without user/maintainer review.
3. **Auditable direct installer for a limited trusted source (not yet built):** feasible only after version/digest/signer metadata is verifiable end to end and Android's required confirmation remains intact.

The core product principle remains: show the evidence, show uncertainty and trade-offs, apply only a policy whose behavior is verified, and say what the operating system prevents PrivaCage from knowing.
