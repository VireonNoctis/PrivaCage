# PrivaCage

**Understand what your device exposes. Block what you can. Know what you cannot.**

PrivaCage is an open-source, local-first privacy auditing project for Android, iOS, and Windows. Its goal is to help people understand app permissions, identify known tracking components, inspect observable network activity, apply enforceable privacy rules, and keep an evidence-backed local audit trail.

PrivaCage is not an anonymity product and does not claim that an ordinary app can observe or disable every operating-system or manufacturer activity. Platform boundaries are part of the product, not fine print.

## Project status

The repository contains the evidence-first tracker intelligence foundation, a Kotlin/JVM DNS core, and an initial Android `VpnService` adapter. The Android app now bundles the canonical tracker database, shows each record's evidence, and allows an explicit import of active domain indicators into the local rules. The Android debug APK and DNS core tests passed GitHub Actions on the current app/core implementation. No emulator or physical-device validation has been completed.

| Area | Status | Honest scope |
|---|---|---|
| Tracker intelligence format | Initial implementation | Seven source-backed endpoint records across analytics, behavioral analytics, and advertising; broad shared domains remain review-only; still small and non-comprehensive |
| Android DNS policy core | Implemented core | Parses supported DNS queries, validates EDNS(0), and returns allow/block/malformed decisions |
| Android DNS packet engine | Implemented core | Processes supplied IPv4 UDP DNS packets, returns REFUSED for configured blocked domains, validates upstream response structure, and retries truncated upstream replies over protected TCP |
| Android VPN adapter | Early implementation; device validation pending | User-approved VPN service, virtual DNS endpoint, TUN loop, locally configured blocked domains, and user-selected IPv4 resolver |
| Tracker list in app | Initial integration | Canonical JSON is bundled and evidence is inspectable; users can explicitly import active domain indicators. Review/retired records are excluded from import; list remains non-comprehensive |
| Encrypted profile transfer | Android + Rust format core | Passphrase-encrypted settings file using Argon2id + AES-256-GCM; Kotlin and Rust decrypt a shared test vector. No account, remote sync, or live DNS encryption |
| APK static analysis | Planned | Findings indicate capability or signatures, not proof of execution |
| Android permission auditing | Planned | Ordinary apps cannot freely revoke other apps' permissions |
| iOS companion | Planned, restricted | Must respect sandbox and NetworkExtension entitlement limits |
| Windows network controls | Planned | Explicit firewall rules require appropriate privileges |
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

- `docs/architecture.md` — system boundaries and data flow.
- `docs/threat-model.md` — assets, threats, and non-goals.
- `docs/privacy-opportunity-backlog.md` — candidate features grounded in real capabilities.
- `docs/security-boundaries.md` — explicit implemented/not-implemented claims and required verification.
- `docs/research-notes/privacy-concerns.md` — sourced privacy concerns and platform constraints.
- `docs/research-notes/tracker-signature-review.md` — evidence and caveats for the initial tracker entries.
- `docs/research-notes/privacy-feature-research-2026-10-23.md` — current sourced privacy feature ideas, feasibility, limits, and integration points.
- `CONTRIBUTING.md` — evidence and review requirements.
- `android-app/` — early Android app, VPN service adapter, local rule configuration, bundled tracker-catalog reader, and Android build workflow.
- `android-core/` — Kotlin/JVM DNS policy evaluator, IPv4 UDP DNS packet codec, packet processor, validated UDP forwarder with upstream TCP fallback, packet-to-packet engine, password-encrypted profile envelope, tests, and Gradle configuration.
- `docs/encrypted-profile-format.md` — stable binary format and security properties for encrypted profile exports.
- `shared/rust/pcage-crypto/` — Rust implementation of the bounded PCAGE01 envelope plus a strict typed profile parser/serializer.
- `shared/crypto/test-vectors/` — shared known-answer fixture decrypted by Kotlin/JVM and Rust tests.
- `shared/tracker-db/schema.md` — tracker database contract.
- `shared/tracker-db/signatures.json` — canonical small, evidence-backed starter dataset bundled by the Android app; not comprehensive.
- `shared/scripts/validate-signatures.py` — standard-library tracker schema and evidence-structure validator.
- `shared/scripts/validate-android-backup.py` — static check for the declared Android backup policy; not an OEM transfer test.
- `tests/test_validate_signatures.py` and `tests/test_android_backup_policy.py` — regression tests for signature evidence and backup configuration.

## Build and test

Requires Python 3.11 or newer for the tracker database validator/tests:

    python shared/scripts/validate-signatures.py
    python shared/scripts/validate-android-backup.py
    python -m unittest discover -s tests -v

The Android app requires JDK 17, Android SDK platform 36, and Gradle 8.14 or compatible:

    cd android-app
    gradle assembleDebug
    gradle :android-core:test

The debug APK is generated at `android-app/app/build/outputs/apk/debug/app-debug.apk`.

The Rust encrypted-profile implementation requires Rust 1.85 or newer:

    cargo test --manifest-path shared/rust/pcage-crypto/Cargo.toml
    cargo clippy --manifest-path shared/rust/pcage-crypto/Cargo.toml --all-targets -- -D warnings

The tracker validator checks structure and URL syntax, not whether evidence is true or still online. An empty database remains valid; additions require human review and explicit caveats. A matching hostname indicates a known service endpoint, not proof that an app collected personal data.

## Platform reality

- Android: a user-approved `VpnService` can route traffic through a local tunnel and enforce supported network rules. The bundled tracker catalog is advisory and opt-in; imported domain rules do not attribute queries to a specific app. This adapter accepts client-facing IPv4 UDP DNS only. It retries a truncated upstream UDP response over a protected TCP socket, but it does not accept DNS-over-TCP connections from apps, filter IPv6 DNS, DoH/DoT/DoQ, inspect HTTPS payloads, or cover every system service or OEM/baseband path. Only one ordinary VPN service can be active at a time.
- iOS: sandboxing prevents one ordinary app from inspecting another app's executable or intercepting its system calls. Network filtering depends on supported NetworkExtension APIs, entitlements, distribution model, and OS policy.
- Windows: firewall rules can block specified traffic when the user has the required privileges. A firewall-rule manager is not unrestricted packet inspection or complete attribution of every system connection.
- IP addresses: a remote endpoint ordinarily sees the public source IP of the network path reaching it. A VPN or proxy changes which intermediary sees that address; it shifts trust rather than making a connection inherently anonymous.
- Static analysis: a permission, SDK, or domain string in an APK is evidence of declared capability or a possible indicator, not proof that the app used it or transmitted personal data.
- Legal requests: a sent request is not proof of deletion.

## Security reporting

Please do not publish details of an unpatched vulnerability involving user data or security controls. Use GitHub's private vulnerability reporting feature if it is available for this repository.

## License

MIT. See LICENSE.
