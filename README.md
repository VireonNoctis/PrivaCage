# PrivaCage

**Understand what your device exposes. Block what you can. Know what you cannot.**

PrivaCage is an open-source, local-first privacy auditing project. Android is the primary mobile implementation; the Svelte and Rust web workspace provides evidence-backed tracker intelligence but is not currently paired to a device. Windows now has a local Go auditor and reversible policy-hardening CLI with explicit UAC elevation, protected rollback state, post-change verification, and optional high-impact network isolation. A separate, pinned Win11Debloat component supplies broader user-selected app removal, Windows customization, optional-feature controls, localized GUI/CLI workflows, and its upstream restore/backup support. An iOS companion remains planned and constrained by Apple's sandbox and entitlement model.

PrivaCage is not an anonymity product. It does not claim that an ordinary app can observe or disable every operating-system, desktop-app, manufacturer, or firmware activity. Platform boundaries are part of the product, not fine print.

## Project status

The repository includes an Android DNS policy core and an early user-approved VPN adapter, evidence-backed tracker intelligence, local APK analysis and metadata scrubbing, encrypted profile export, optional local DNS-history export with signed audit checkpoints, a Rust portable checkpoint verifier, Rust sync protocol/relay components, a Svelte 5 + TypeScript web console backed by Rust/Axum, and a Windows CLI that audits selected settings and applies documented reversible privacy policies. Windows policy writes are restricted to an allowlist, require confirmation and elevation, save a SYSTEM/Administrators-only backup, verify observed values, and provide a restore path. These are distinct maturity levels: Android VPN routing and backup behavior still need representative device validation; web device pairing/event ingestion is not connected; Windows policy controls do not guarantee zero Windows traffic or cover every OS component, driver, firmware, or network route.

| Area | Status | Honest scope |
|---|---|---|
| Tracker intelligence format | Expanded foundation | Fifteen source-backed endpoint records across analytics, behavioral analytics, advertising, crash reporting, and mobile attribution; broad shared domains remain review-only; still small and non-comprehensive |
| Android DNS policy core | Implemented core | Parses supported DNS queries, validates EDNS(0), returns allow/block/malformed decisions, supports offline rule previews, and records aggregate outcomes; an explicitly opt-in local event history can store hostnames with best-effort socket-owner attribution |
| Android DNS packet engine | Implemented core | Processes supplied IPv4 UDP DNS packets, returns REFUSED for configured blocked domains, validates upstream response structure, and retries truncated upstream replies over protected TCP |
| Android VPN adapter | Early implementation; device validation pending | User-approved VPN service, preflight disclosure, process-aware lifecycle status, one-query protected-upstream DNS route diagnostics, Android-visible captive-portal/validation snapshots, virtual DNS endpoint, TUN loop, configured domain rules, and optional DNS-over-TLS with hostname verification and no plaintext fallback |
| Tracker list in app | Initial integration | Canonical JSON is bundled and evidence is inspectable; users can explicitly import active domain indicators. Review/retired records are excluded from import; list remains non-comprehensive |
| Encrypted profile transfer | Android + Rust format core | Passphrase-encrypted settings file using Argon2id + AES-256-GCM; Kotlin and Rust share v1/v2 schema support and decrypt a known-answer vector. No account or remote sync; DNS-over-TLS is optional |
| E2EE sync protocol core | Rust protocol + Android client integration | Owner-signed roster snapshots publish to an authenticated relay with a bounded 128-revision history; Android pulls and verifies updates before inbox processing, records bounded local lifecycle events, stages peer-key rotation behind owner approval, and supports dual-signed owner-key transitions bound to the exact space/revision. The public handoff package is retained for re-copying and recovery/another rotation are gated until user acknowledgement. Replacement owner fingerprints still require independent confirmation; relay-admin credential provisioning remains separate. No iOS/Windows client, background push, conflict resolution, or physical-device lifecycle validation yet |
| Opaque sync relay | Rust + SQLite loopback service | Legacy per-space capability migration plus admin-managed per-device tokens, validated public cards, signed HTTP proof-of-possession, 120-second timestamp window, durable nonce replay rejection, selective credential revocation, bounded opaque storage, 7-day retention, duplicate-ID rejection, and bounded cursor pagination. Remote use requires a TLS reverse proxy |
| Multi-format metadata inspector | Rust core + Android JNI + selected-file UI | Local inspection and separate cleaned copies for JPEG, PNG, and WebP; bounded streaming parsers, PNG CRC checks, malformed-file rejection, output re-parse before save, no image recompression or upload. Color profiles and unknown extension chunks can retain metadata; pixel content is not anonymized |
| APK static audit | Initial implementation | User-selected APKs are parsed locally for declared permissions, exported components, version/target SDK, and SHA-256; bounded DEX string scans check catalog domain/SDK literals, including supported terminal package wildcards (`.*` and `.**`). These are possible indicators, not proof of runtime use or malicious behavior |
| Android permission auditing | Local device snapshot + launcher-visible app audit | Reads exposed location-services, Wi-Fi radio, Private DNS mode, active-default-network VPN state, PrivaCage's own declared permissions, and requested/granted dangerous permissions for launcher-visible apps. It does not inventory every system/OEM service or prove live collection; it never uploads the inventory |
| Platform privacy controls | Official settings links | Opens Android ad privacy settings where supported, Google Account Data & Privacy, and Samsung Customization Service privacy information. Users must review and change settings themselves; opening a page is not an opt-out |
| Windows privacy auditor and hardening CLI | Implemented slice; Windows CI validated | Reads selected state and applies a narrow allowlist with preview, protected backup, verification, and restore. Separate pinned Win11Debloat component offers broad optional customization; its actions are initiated separately by the user and are not covered by the audit CLI's rollback transaction. |
| iOS companion | Planned, restricted | Must respect sandbox and NetworkExtension entitlement limits |
| Windows egress controls | Opt-in, disruptive | Optional outbound-default Block or all-program outbound block rule; these can break DNS, Windows Update, cloud apps and other networking, and do not prove that kernel/driver/firmware/out-of-band paths are silent |
| Legal request assistant | Planned | Drafts and tracks requests; cannot verify deletion from company systems |

## Principles

- Local-first: core auditing should work without an account or required cloud service.
- No product telemetry by default.
- Evidence over fear: distinguish observed facts, static indicators, inferences, and unknowns.
- Enforcement must be real: controls must apply an OS-level action and report its outcome.
- Least privilege: elevated access needs a clear purpose and explicit explanation.
- Reproducible and testable: data formats and security-sensitive rules require validation.
- No paid placement in recommendations or tracker intelligence.

## Repository map

- `web/` — responsive Svelte 5 + TypeScript web console built as static assets; no JavaScript backend routes.
- `web-backend/` — Rust/Axum API for the canonical tracker catalogue, derived summary metrics, service health, and explicit capability boundaries. Binds to loopback by default.
- `.github/workflows/web-validation.yml` — Svelte/TypeScript checks, frontend tests, production build, Rust formatting, and Rust API tests.

- `windows/pcage-audit/` — local Windows privacy audit, reversible documented-policy controls, and explicit handoff to the pinned Win11Debloat customization toolkit.
- `windows/Win11Debloat/` — pinned MIT-licensed upstream Win11Debloat submodule; initialize with `git submodule update --init --recursive`.
- `docs/architecture.md` — system boundaries and data flow.
- `docs/threat-model.md` — assets, threats, and non-goals.
- `docs/privacy-opportunity-backlog.md` — candidate features grounded in real capabilities.
- `docs/security-boundaries.md` — explicit implemented/not-implemented claims and required verification.
- `docs/research-notes/privacy-concerns.md` — sourced privacy concerns and platform constraints.
- `docs/research-notes/tracker-signature-review.md` — evidence and caveats for the initial tracker entries.
- `docs/research-notes/privacy-feature-research-2026-10-23.md` — sourced privacy feature ideas, feasibility, limits, and integration points.
- `docs/research-notes/go-tooling-and-android-backup-audit-2026-10-25.md` — Go tooling migration findings, Android backup/restore limits, and concrete remediation plans.
- `CONTRIBUTING.md` — evidence and review requirements.
- `android-app/` — early Android app, VPN service adapter, local rule configuration, bundled tracker-catalog reader, offline APK audit, Rust-powered JPEG/PNG/WebP metadata inspection and scrubbing, and Android build workflow.
- `shared/rust/pcage-metadata/` — platform-neutral Rust metadata inspection/scrubbing core and local CLI for JPEG, PNG, and WebP.
- `shared/rust/pcage-metadata-jni/` — Android native bridge for the Rust metadata core. The Android flow previews recognized metadata, creates a separate copy, re-inspects it, and only then offers save.
- `android-core/src/main/kotlin/org/privacage/metadata/JpegMetadataScrubber.kt` — legacy Kotlin JPEG-only parser retained for compatibility/tests; the current Android UI uses the Rust multi-format core.
- `android-core/src/main/kotlin/org/privacage/audit/PermissionRiskClassifier.kt` — conservative classification of known manifest permission declarations; unknown permissions stay unclassified.
- `android-core/` — Kotlin/JVM DNS policy evaluator, IPv4 UDP DNS packet codec, packet processor, validated UDP forwarder with upstream TCP fallback, certificate-verified DNS-over-TLS transport, packet-to-packet engine, password-encrypted profile envelope, tests, and Gradle configuration.
- `docs/encrypted-profile-format.md` — stable binary format and security properties for encrypted profile exports.
- `docs/audit-checkpoint-format.md` — signed audit checkpoint v1 wire format, hash-chain rules, limits, and trust boundary.
- `shared/rust/pcage-audit/` — offline Rust CLI/library to verify signed Android audit checkpoints without network access.
- `shared/audit/test-vectors/checkpoint-v1.json` — fixed, test-only signed interoperability vector (no private key included).
- `shared/rust/pcage-crypto/` — Rust implementation of the bounded PCAGE01 envelope plus a strict typed profile parser/serializer.
- `shared/rust/tracker-intelligence/` — Rust tracker catalog and schema-v2 intelligence tooling; release manifests use Ed25519-signed metadata, a sequential predecessor-linked release history, expiry checks, a signed current pointer, and optional externally persisted rollback floors. This is a local release store, not a remote catalog updater or full TUF client; see its README for the key-management and rollback boundary.
- `shared/rust/pcage-sync/` — Rust end-to-end sync protocol primitives for device identity cards, signed recipient-encrypted messages, replay protection, dual-signed peer/owner key rotation, and recovery bundles.
- Android sync peer management maintains a local denylist and removes pending profiles when a trusted fingerprint is revoked. This is device-local trust revocation; shared relay capability rotation is a separate administrator action and invalidates all devices using that capability.
- `shared/rust/pcage-sync-relay/` — SQLite-backed loopback HTTP relay that stores opaque sync packets and never decrypts them.
- `shared/rust/pcage-sync-jni/` — native bridge used by Android to call the Rust identity, packet-sealing, packet-opening, and recovery APIs.
- `android-app/app/src/main/kotlin/org/privacage/android/sync/` — Android Keystore-protected local sync record, native bridge facade, HTTPS relay client, and explicit-trust/send/receive orchestration.
- `docs/e2ee-sync-protocol.md` — protocol format, trust assumptions, and implementation boundaries.
- `shared/crypto/test-vectors/` — shared known-answer fixture decrypted by Kotlin/JVM and Rust tests.
- `shared/tracker-db/schema.md` — tracker database contract.
- `shared/tracker-db/signatures.json` — canonical small, evidence-backed starter dataset bundled by the Android app; not comprehensive.
- `shared/go/pcage-tools/` — standard-library Go CLI for tracker schema/freshness validation, tracker review reporting, Android backup declaration checks, and the Android sensitive-permission/known-telemetry dependency baseline. Its tests replace the Python regression suite; the backup check remains static and is not an OEM transfer test.
- `windows/pcage-audit/` — Go CLI and monochrome interactive console for Windows baseline auditing, edition-aware hardening preview/apply, UAC elevation, protected rollback backup, verification, restoration, and explicit network-isolation options. Includes unit tests and Windows/Linux CI; see its README and the Windows hardening research note for limits.

## Build and test

Requires Go 1.27 or newer for the repository privacy tools and regression tests:

    cd shared/go/pcage-tools
    go test ./...
    go run . validate-tracker --max-age-days 180
    go run . tracker-report --format markdown
    go run . validate-android-backup
    go run . validate-android-privacy

### Windows privacy audit and hardening

The collector and hardening operations run on Windows 10/11 with Windows PowerShell and the NetSecurity module. Unit tests and Go compilation also run on Linux, but policy mutation and the live collector are Windows-only.

From `windows/pcage-audit` on Windows:

    go test ./...
    go run . audit --format text
    go run . plan --profile balanced
    go run . plan --profile strict
    go run . apply --profile balanced --confirm
    go run . verify
    go run . restore --confirm-restore

The interactive monochrome console opens with `go run .` in a terminal. Apply and restore request UAC elevation. An apply refuses to overwrite an existing backup until the previous profile is restored. The protected backup is written under `%ProgramData%\PrivaCage\hardening-backup.json`.

**High-impact network controls are separate and opt-in.** Preview before applying:

    go run . plan --profile balanced --block-outbound-by-default --confirm-network-disruption
    go run . apply --profile balanced --block-outbound-by-default --confirm --confirm-network-disruption
    go run . plan --profile balanced --isolate-network --confirm-network-disruption
    go run . apply --profile balanced --isolate-network --confirm --confirm-network-disruption

The outbound-default mode changes all three firewall profiles' default outbound action; existing explicit allow rules may still permit some connections. Emergency isolation adds an all-program outbound block rule and may immediately break the internet, DNS, Windows Update, cloud features, downloads, and network-dependent apps. Use a local console and know how to run `restore` before enabling it.

The Android app requires JDK 17, Android SDK platform 36, Gradle 8.14 or compatible, and Android NDK 27.2.12479018. Build the Rust JNI libraries before Gradle (GitHub Actions does this automatically):

    sdkmanager "ndk;27.2.12479018"
    cargo install cargo-ndk --version 3.5.4 --locked
    rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
    cd shared/rust/pcage-sync-jni
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ../../../android-app/app/src/main/jniLibs build --release
    cd ../../../android-app
    gradle assembleDebug
    gradle :android-core:test
    gradle :app:testDebugUnitTest

The debug APK is generated at `android-app/app/build/outputs/apk/debug/app-debug.apk`.

The Rust encrypted-profile and metadata implementations require Rust 1.85 or newer:

    cargo test --manifest-path shared/rust/pcage-crypto/Cargo.toml
    cargo clippy --manifest-path shared/rust/pcage-crypto/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path shared/rust/pcage-metadata/Cargo.toml
    cargo clippy --manifest-path shared/rust/pcage-metadata/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path shared/rust/pcage-metadata-jni/Cargo.toml
    cargo clippy --manifest-path shared/rust/pcage-metadata-jni/Cargo.toml --all-targets -- -D warnings

The portable audit checkpoint verifier requires Rust 1.85 or newer. It rejects unsupported fields, oversized inputs, false redaction claims, chain mismatches, invalid P-256 signatures, and inconsistent counts; a valid signature does not establish the signer’s identity.

    cargo fmt --manifest-path shared/rust/pcage-audit/Cargo.toml --all -- --check
    cargo test --manifest-path shared/rust/pcage-audit/Cargo.toml
    cargo clippy --manifest-path shared/rust/pcage-audit/Cargo.toml --all-targets -- -D warnings
    cargo run --manifest-path shared/rust/pcage-audit/Cargo.toml -- path/to/checkpoint.json

The E2EE sync protocol core and Android JNI bridge require Rust 1.85 or newer:

    cargo test --manifest-path shared/rust/pcage-sync/Cargo.toml
    cargo clippy --manifest-path shared/rust/pcage-sync/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path shared/rust/pcage-sync-jni/Cargo.toml
    cargo clippy --manifest-path shared/rust/pcage-sync-jni/Cargo.toml --all-targets -- -D warnings

The tracker-intelligence release tooling uses Rust 1.85 or newer. It validates legacy catalog schema v1 and intelligence bundle schema v2, and supports locally signed release snapshots. Keep the 32-byte Ed25519 signing seed outside the repository and shell history; pin the public key out of band.

    cargo test --manifest-path shared/rust/tracker-intelligence/Cargo.toml
    cargo run --manifest-path shared/rust/tracker-intelligence/Cargo.toml -- publish path/to/catalog.json ./release-store release-2026-10-25 2026-10-25 "$PCAGE_ED25519_SEED_HEX"
    cargo run --manifest-path shared/rust/tracker-intelligence/Cargo.toml -- verify-current ./release-store "$PCAGE_TRUSTED_PUBLIC_KEY_HEX" "$PCAGE_MINIMUM_RELEASE_SEQUENCE" "$PCAGE_MINIMUM_STATE_REVISION"
    cargo run --manifest-path shared/rust/tracker-intelligence/Cargo.toml -- history ./release-store "$PCAGE_TRUSTED_PUBLIC_KEY_HEX"

An intentional local rollback requires the signing seed, signs a new current pointer, and preserves the release-chain head:

    cargo run --manifest-path shared/rust/tracker-intelligence/Cargo.toml -- rollback ./release-store release-2026-10-23 "$PCAGE_ED25519_SEED_HEX"

The minimum sequence and pointer revision must be persisted by the caller outside the release store to detect signed pointer replay. No remote updater, release-signing-key rotation, or full TUF client is implemented.

The opaque relay service requires Rust 1.85 or newer:

    cargo test --manifest-path shared/rust/pcage-sync-relay/Cargo.toml
    cargo clippy --manifest-path shared/rust/pcage-sync-relay/Cargo.toml --all-targets -- -D warnings

The tracker validator checks structure and URL syntax and can enforce an evidence-review age limit (CI uses 180 days); it does not prove that evidence is true or the URL is still online. An empty database remains valid; additions require human review and explicit caveats. A matching hostname indicates a known service endpoint, not proof that an app collected personal data.

## Platform reality

- Android: a user-approved `VpnService` can route traffic through a local tunnel and enforce supported network rules. The bundled tracker catalog is advisory and opt-in; imported domain rules do not attribute queries to a specific app. The editor includes an offline hostname-rule preview and aggregate session counters. Optional local DNS event history is disabled by default and can retain hostnames; socket-owner lookup is best-effort and may identify Android's resolver rather than the initiating app. An explicit diagnostic sends one fixed `example.com` A query via the configured protected upstream, samples Android-visible non-VPN network validation/captive-portal state, and compares the snapshot around the test; it stores neither raw DNS packets nor query names. This does not prove every app uses the expected path, and Wi-Fi/mobile handover and captive-portal behavior still require device validation. A local device snapshot reports exposed location, Wi-Fi, Private DNS, and active-network VPN settings plus PrivaCage's own declared permissions, without reading SSIDs or uploading the snapshot. A separate permission audit checks dangerous permissions declared by launcher-visible apps and reports current grant flags locally; Android package visibility means this is not a complete inventory of system/OEM services. This adapter accepts client-facing IPv4 UDP DNS only. It retries a truncated upstream UDP response over a protected TCP socket, but it does not accept DNS-over-TCP connections from apps, filter IPv6 DNS, DoH/DoT/DoQ, inspect HTTPS payloads, or cover every system service or OEM/baseband path. Only one ordinary VPN service can be active at a time.
- iOS: sandboxing prevents one ordinary app from inspecting another app's executable or intercepting its system calls. Network filtering depends on supported NetworkExtension APIs, entitlements, distribution model, and OS policy.
- Windows: the local CLI reads firewall profiles and selected policy values, then applies a restricted allowlist of supported privacy policies after explicit confirmation and UAC elevation. It records the original registry/firewall state in a protected local backup, verifies applied policy values, and provides a restore path. Its firewall isolation option is deliberately separate and disruptive. It cannot inspect every live connection or prove that all Windows components have stopped communicating.
- Wi-Fi and connection privacy: a Wi-Fi operator can usually observe connected-device/network metadata, timing, traffic volume, and destination IPs. HTTPS protects application content in transit; encrypted DNS can hide DNS questions from the local network when correctly configured, while the resolver still sees them. A VPN hides tunneled destinations from the local Wi-Fi operator but shifts visibility and trust to the VPN provider; it does not prove every connection is tunneled.
- Static APK manifest audit: PrivaCage can inspect a user-selected APK's declared permissions and exported components locally without installing it. A declared permission, exported component, SDK string, or domain is evidence of capability/surface, not proof of runtime behavior or data collection.
- Legal requests: a sent request is not proof of deletion.

## Windows privacy controls — claim boundary

The balanced profile minimizes documented policy surfaces including optional diagnostic data, advertising ID, Activity Feed/user-activity upload, tailored experiences, online speech personalization, and supported Windows 11 diagnostic-log/dump collection limits. On mainstream Pro editions, PrivaCage selects Required diagnostic data and locks the end-user diagnostic-data selector in Settings on supported builds. The Diagnostic data off value (0) is supported only on Enterprise, Education, and Server editions; it controls Windows diagnostic data, not every system communication.

The strict profile additionally disables clipboard history, force-denies selected Windows-app capabilities, and disables Windows Error Reporting. These policies are not a universal barrier against classic desktop programs, system services, drivers, or firmware. Domain policy or MDM may override local settings. The app preserves Defender, Windows Update, SmartScreen, licensing, and certificate validation.

The CLI makes no network requests itself. Registry changes are allowlisted, saved with their prior values, checked after writing, and reversible through the captured backup. The backup is restricted to SYSTEM and Administrators. Network controls require extra confirmation; an all-program outbound block is not appropriate for normal daily operation and cannot prove every out-of-band channel is silent. Read [the research note](docs/research-notes/windows-privacy-hardening-2026-10-25.md) and [the tool guide](windows/pcage-audit/README.md) before applying policies.

## Security reporting

Please do not publish details of an unpatched vulnerability involving user data or security controls. Use GitHub's private vulnerability reporting feature if it is available for this repository.

## License

MIT. See LICENSE.


| JPEG metadata inspection and removal | Local report before save | Reports input/output sizes and removed APP1 (EXIF/XMP), APP13 (IPTC/Photoshop), and COM counts; second-pass verification checks those classes are absent. Other APP markers are preserved, and the report does not enumerate every embedded field or guarantee complete metadata removal. |


### Android encrypted sync scope

The Android sync UI sends only the current DNS settings profile to an explicitly trusted public device card. Before trusting a peer, compare the complete SHA-256 fingerprint over a separate trusted channel; the relay itself is not a trust authority. Relay URLs must use HTTPS and redirects are rejected. Identity and relay capability are stored inside an Android Keystore-encrypted record. Recovery exports are separate passphrase-encrypted files and should be kept offline. Import restores the same cryptographic identity; it does not create a distinct device identity or revoke the original installation. Peer revocation is local to each installation, while relay capability rotation invalidates every device sharing that space token. The relay still observes metadata, and physical-device lifecycle testing remains outstanding.
