# PrivaCage

**Understand what your device exposes. Block what you can. Know what you cannot.**

PrivaCage is an open-source, local-first privacy auditing project. It combines evidence-backed tracker intelligence, a bounded Android DNS filter, local APK and permission audits, encrypted configuration transfer, metadata inspection, and reversible Windows privacy-policy controls.

PrivaCage is **not** an anonymity product or a universal monitoring agent. Ordinary apps cannot reliably inspect every other app, override all OS permissions, decrypt arbitrary application traffic, or control firmware and manufacturer services. Those boundaries are part of the design—not fine print.

## Contents

- [Project status](#project-status)
- [Core capabilities](#core-capabilities)
- [Android DNS policy and packet engine](#android-dns-policy-and-packet-engine)
- [Tracker intelligence](#tracker-intelligence)
- [APK and permission auditing](#apk-and-permission-auditing)
- [Encrypted profiles and sync](#encrypted-profiles-and-sync)
- [Privacy-focused app alternatives](#privacy-focused-app-alternatives)
- [Windows privacy audit and hardening](#windows-privacy-audit-and-hardening)
- [Web and iOS](#web-and-ios)
- [Architecture and repository map](#architecture-and-repository-map)
- [Development and validation](#development-and-validation)
- [Security boundaries](#security-boundaries)
- [Research and contribution](#research-and-contribution)
- [License](#license)

## Project status

Features do not all have the same maturity. A coded path is not the same as a tested device behavior.

| Area | Current status | What that means |
|---|---|---|
| Tracker intelligence | Expanded catalogue; schema v1 | 25 source-backed indicator records with typed domain/SDK indicators, confidence, status, review date and evidence links. Useful but not comprehensive. |
| Android DNS policy | Implemented core | Validates a restricted classic-DNS subset, normalizes host rules, and produces explicit allow/block/malformed results. |
| Android DNS packet engine | IPv4 + constrained IPv6 UDP-DNS path | Validates packet lengths/checksums, blocks configured names, forwards allowed queries, and builds packet responses. IPv6 extension headers, fragments and jumbograms are intentionally rejected. |
| Android VPN adapter | Early implementation; device validation pending | Routes only the configured virtual IPv4/IPv6 DNS endpoints, protects upstream sockets, supports optional DNS-over-TLS, and reports aggregate counters. It is not a general traffic VPN. |
| In-app tracker list | Bundled catalogue and explicit import | Evidence and lifecycle status are inspectable. Only active domain indicators can be added to the rule editor; the user must save the resulting rules. |
| APK static audit | Local static inspection | Reports package/version/target SDK, requested permissions, exported components, SHA-256, signer metadata, APK signature integrity and bounded DEX string matches. |
| Permission audit | Launcher-visible inventory + local drift baseline | Compares dangerous-permission declarations/grant flags between complete scans. Does not claim to see every installed/system package or live permission use. |
| Encrypted profile transfer | Android implementation + shared format | PCAGE01 passphrase-encrypted profile files use Argon2id and AES-256-GCM. This protects file contents but does not authenticate the sender. |
| E2EE sync | Rust protocol/relay and Android integration | Uses device identity, signed trust-roster state and encrypted payloads. Physical-device lifecycle, recovery and end-to-end integration still require validation. |
| Metadata inspection/scrubbing | Rust core + Android UI | Handles JPEG, PNG and WebP with bounded parsing and output verification; it is not a universal metadata or visual-content anonymizer. |
| Signed audit checkpoint comparison | Android + Web, local-only | Verifies both signatures, payload digests and record chains before comparing same-key, same-scope hash sequences. It cannot establish identity, trusted time or event completeness. |
| Privacy-rights drafts | Android local workflow | Produces user-reviewed UK GDPR / California CCPA drafts and a user-guided DROP checklist. Nothing is sent automatically; legal review is required before release. |
| Alternative-app picker | 29 curated options and local queue | Lets users select replacements, choose an available store/project source, and open the queue one item at a time. Download and install stay with that source and Android. |
| Windows privacy tooling | Local Go auditor + reversible policy CLI | Read-only audit and documented, allowlisted policy changes with explicit confirmation, UAC, protected backup, verification and restore. Network isolation is separate and disruptive. |
| Web console | Svelte 5 + TypeScript, Rust/Axum API | Displays tracker intelligence. It is not yet a live-device event ingestion dashboard. |
| iOS | Planned / constrained | Must use public APIs and approved NetworkExtension capabilities; an ordinary iOS app cannot inspect other apps' binaries or override their permissions. |

## Core capabilities

### Local-first audits

- User-selected APK inspection without installing or executing the package.
- On-device permission snapshots and comparison history.
- A bundled, evidence-linked tracker catalogue.
- Optional local DNS event history, disabled by default, encrypted at rest with an AES-GCM key in Android Keystore, with bounded retention controls; recorded events include the hostname, decision, and best-effort socket-owner label.
- Encrypted profile export/import through Android's document picker.
- Local metadata inspection and separate cleaned copies for supported image formats.
- Windows baseline reports and policy changes that can be verified and restored.

### Principles

- **Evidence over fear:** distinguish direct observations, static indicators, inferences and unknowns.
- **No product telemetry by default:** local reports are not silently uploaded.
- **Least privilege:** elevated access is gated and explained.
- **No ghost controls:** a UI control must invoke an actual action, or its limitation must be stated.
- **Reversibility:** security-sensitive Windows changes save prior state and provide restore paths.
- **No paid placement:** alternatives and tracker entries are not sponsored rankings.
- **Accurate uncertainty:** a tracker indicator does not prove an app transmitted personal data.

## Android DNS policy and packet engine

The DNS engine is in `android-core/`; the Android VPN adapter is in `android-app/`.

### What it does

1. Evaluates a restricted subset of classic DNS queries with one question and validated EDNS(0) data.
2. Matches exact domains and label-boundary subdomains rather than arbitrary string substrings.
3. Processes IPv4 UDP DNS and a constrained IPv6 UDP DNS format. It validates declared lengths and checksums and rejects unsupported packet shapes.
4. Returns a DNS REFUSED reply for a blocked hostname or forwards allowed query data through a configured upstream transport.
5. Validates upstream response structure and retries truncated upstream UDP responses over a protected TCP connection.
6. Optionally uses DNS-over-TLS for PrivaCage's upstream resolver with certificate/hostname verification and no plaintext fallback.
7. Keeps core counters aggregate-only; DNS query names and packet contents are not retained by the core engine.

The Android service routes only its virtual DNS endpoints, not all IP traffic. Upstream sockets are protected from re-entering the VPN.

### Important limits

- The client-facing path handles UDP DNS, not DNS-over-TCP initiated by apps.
- IPv6 extension headers, IPv6 fragments and jumbograms are rejected. Replies that exceed the configured 1,500-byte TUN MTU are dropped rather than silently truncated.
- This is not a general packet firewall or kill switch. It does not decode DoH/DoQ, arbitrary app tunnels, direct-IP connections, or HTTPS payloads.
- DNS-over-TLS for PrivaCage's upstream does not force unrelated apps to use that resolver.
- The engine does not reliably attribute every DNS query to its originating app.
- Routing, revocation, lifecycle, OEM differences and resolver behavior still require emulator and physical-device validation. Unit tests cannot establish device-level coverage.

Implementation notes and test commands are in [the Android core README](android-core/README.md) and [architecture guide](docs/architecture.md).

## Tracker intelligence

The canonical catalogue is `shared/tracker-db/signatures.json`; its schema is documented in [shared/tracker-db/schema.md](shared/tracker-db/schema.md).

Each record includes:

- A stable identifier, name and category.
- Typed indicators: domain hostnames and/or SDK class patterns.
- Confidence and lifecycle status: `active`, `review`, or `retired`.
- A last-reviewed date and HTTPS evidence sources.

The catalogue contains 25 indicators across analytics, behavioral analytics, advertising, crash reporting, mobile attribution and push/engagement SDKs. It is intentionally small relative to the software ecosystem.

**Interpretation rules:** domain presence identifies an endpoint, not an initiating app. SDK string presence is a static indicator, not proof of initialization or transmission. Confidence describes the indicator-to-service association, not a probability that the scanned app is malicious. The app's DNS filter cannot enforce Java/Kotlin class-name matches.

The in-app list bundles the canonical JSON. Users can inspect evidence and explicitly import active domain indicators into the DNS rule editor. Importing does not automatically save or turn them on. Review and retired entries are not bulk-imported.

The optional local DNS event-history view also compares recorded query hostnames against the bundled domain indicators. Matching is case-insensitive and label-boundary-aware (a suffix such as `tracker.example.attacker.invalid` does not match `tracker.example`). It shows catalogue status, confidence, review date and an evidence URL where available. Each stored event also contains the DNS decision and a best-effort socket-owner label; Android's system resolver may own the observed socket, so the label may not identify the initiating app. This is an informational correlation only: it does not change DNS rules, prove which app initiated the query, or reveal payload contents. “No match” is not a privacy/safety verdict. If the catalogue failed to load, the UI reports the lookup as unavailable instead of reporting a clean result. The opt-in history is encrypted at rest with an AES-GCM key held by Android Keystore, capped at 100 events and 256 KiB of serialized UTF-8 plaintext, and rejects oversized or malformed saved records. On first access after upgrading from a prior build, PrivaCage encrypts the legacy plaintext history and removes that old value only after the encrypted copy is confirmed stored. If the Keystore key is missing or authentication fails, it preserves the ciphertext and fails closed instead of creating a replacement key or claiming the history is empty. Retention defaults to 7 days and can be set to 24 hours, 7 days, or 30 days. Expired records are pruned when PrivaCage opens or accesses history through recording, refresh, or export; no background worker runs solely to delete history, so expiry is applied on the next app use. If stored history or any timestamp is unreadable, new events are not written over it, the history view reports the problem, pruning stops without partially deleting the remaining evidence, and export fails rather than silently omitting records; the user must explicitly clear the history to start fresh.

Validate the schema and review-freshness report with:

```sh
go -C shared/go/pcage-tools test ./...
go -C shared/go/pcage-tools run . validate-tracker --max-age-days 180
go -C shared/go/pcage-tools run . validate-app-alternatives
go -C shared/go/pcage-tools run . app-alternatives-report --max-age-days 180 --fail-stale --format json
go -C shared/go/pcage-tools run . tracker-report --format markdown
```

A hosts feed or a match count is not proof of tracking behavior. Candidate feed updates should be staged, sourced, reviewed and diffed before they become active rules.

## APK and permission auditing

### Static APK audit

The Android APK inspector works on a user-selected file, with a 100 MiB input limit. It reports package and version metadata, target SDK, declared permissions, exported components, SHA-256, available signer certificate fingerprints, APK signature integrity, and bounded DEX string matches against the tracker catalogue.

It does not install or execute the APK, upload it, or dynamically observe its behavior. APK signature verification confirms integrity under the supported signing checks; it does **not** prove that the publisher is reputable. A matching SDK class is not evidence that events were actually sent.

### Permission audit

The local audit lists dangerous permissions declared by launcher-visible apps and Android's exposed grant flags. A local baseline can compare subsequent complete scans and report newly requested permissions, newly granted permissions, revoked grants, and permissions no longer requested. Packages that disappear from the scan are reported separately; their disappearance is not misrepresented as permission revocation.

The audit does not use `QUERY_ALL_PACKAGES` to claim a complete device inventory. Android package visibility, work profiles, manufacturer services and privileged/headless components can limit what is visible. Permission declarations do not prove live camera, microphone or sensor use, and the grant inventory is not a network-traffic monitor.

The baseline is stored in app-private local preferences and can be cleared from the dashboard. PrivaCage does not silently revoke permissions belonging to other applications.

## Encrypted profiles and sync

### Portable `.pcage` profile

The PCAGE01 file envelope uses a fixed Argon2id v1.3 parameter set to derive a key, then AES-256-GCM with a fresh nonce and authenticated header. Android encrypts before writing the file through the Storage Access Framework. Kotlin/JVM and Rust share a known-answer test fixture.

The file contains settings, not a live traffic tunnel. It does not identify/authenticate the sender. The receiver needs both the file and passphrase, which should be conveyed through a separate trusted channel. Losing the passphrase means the export cannot be decrypted.

See [the byte-level format](docs/encrypted-profile-format.md).

### E2EE sync

The separate sync implementation uses device identity keys, signed roster state, recipient-bound encrypted profiles and an authenticated relay protocol. First trust decisions require independent fingerprint verification, and relay access metadata remains visible to the relay. A recovery bundle restores the same identity; it is not equivalent to generating a new device identity.

Sync protocol guarantees and remaining boundaries are documented in [docs/e2ee-sync-protocol.md](docs/e2ee-sync-protocol.md). Physical-device lifecycle validation remains necessary.

## Privacy-focused app alternatives

The alternative catalogue is `shared/app-alternatives/catalog.json`. It currently includes 29 curated replacements for common Google-suite and adjacent services, spanning email, cloud storage, photos, maps, browsers, search, video, calendar, notes, keyboards, authenticators, contacts, app repositories, messaging, video calls, passwords, RSS, translation and documents.

The Android screen lets a user filter by the Google app being replaced, select one or more alternatives, choose one of the source links for each item, and store a local sequential queue. It shows both the reason to consider an app and its trade-offs. Source destinations are validated as HTTPS URLs against an exact reviewed-host allowlist.

### Why the queue does not silently sideload APKs

The current catalogue contains reviewed store/project landing pages—not version-pinned APK artifacts with maintained SHA-256 and signing-certificate metadata. The app opens one selected source at a time, where the source controls downloads and Android preserves its normal install confirmation. A queue item's “completed” tick is a user reminder; PrivaCage does not pretend it can verify installation simply because an external page was opened.

Automatic artifact downloading should only be added with a verifiable source index, pinned release metadata, digest and signer checks, bounded downloads, redirect policy, expiry/revocation handling, and a clear Android package-installer handoff. Do not bypass Play Protect, Android installer consent, or publisher/signature checks to make the UI appear more automated. The implementation and research trade-offs are in [the privacy-suite research note](docs/research-notes/privacy-suite-expansion-2026-10-25.md).

## Windows privacy audit and hardening

The Go tool under `windows/pcage-audit/` provides a read-only local audit and a reversible policy-hardening workflow. The read-only report covers the three firewall profiles, selected diagnostic-data and Windows App Privacy policies, adapter DNS resolver addresses, and current-user WinINET proxy-state flags. It does not print proxy hostnames/PAC URLs or claim that resolver transport is encrypted. Policy changes are limited to an allowlist and require explicit confirmation and UAC elevation; prior values are backed up under protected permissions, writes are checked, and restore verifies the recovered state.

### Profiles and policy boundaries

- **Balanced** reduces selected documented Windows privacy surfaces, including optional diagnostic data where supported, advertising ID, Activity Feed/User Activity, tailored experiences and online speech personalization. On common Pro editions, Required diagnostic data remains; the selector may be locked on supported builds.
- **Strict** includes balanced policies, disables clipboard history, applies selected Windows-app capability force-denials and disables Windows Error Reporting policy.
- **Outbound-default block** and **emergency all-program outbound isolation** are separate, high-impact actions. They can interrupt DNS, Windows Update, cloud applications, downloads and remote administration.

Microsoft documents that the “Diagnostic data off” value for the described policy is supported only on specified Enterprise, Education and Server editions; the extra diagnostic-log and dump controls apply to Windows 11 and Windows Server 2022. Local policy values can be overridden by domain policy or MDM. None of these settings guarantees zero Windows communications or controls all desktop applications, services, drivers, firmware or external network paths.

Read the [Windows tool guide](windows/pcage-audit/README.md) and [Windows privacy research](docs/research-notes/windows-privacy-hardening-2026-10-25.md) before applying changes. The separately pinned [Win11Debloat component](windows/Win11Debloat/) is user-selected software and is not covered by the audit CLI's rollback transaction.

## Web and iOS

- `web/` is a Svelte 5 + TypeScript static client.
- `web-backend/` is a Rust/Axum API serving validated tracker catalogue data.
- The web client does not invent device events or claim that a tracker was observed on a user's device. Live-device pairing and event ingestion are not yet connected.
- iOS work must stay within Apple's sandbox and approved NetworkExtension entitlements. An ordinary iOS app cannot scan other apps' executable binaries or override their permissions.

## Architecture and repository map

```text
.
├── android-core/                  # Kotlin/JVM DNS policy, packet engine and audit models
├── android-app/                   # Android UI, VPN adapter, APK/permission audit
├── shared/
│   ├── tracker-db/                # canonical evidence-backed tracker catalogue
│   ├── app-alternatives/          # reviewed alternative-app catalogue
│   ├── go/pcage-tools/            # tracker and Android privacy validation tools
│   ├── rust/pcage-crypto/         # portable encrypted profile implementation
│   └── rust/pcage-sync/           # sync protocol components
├── web/                           # Svelte 5 + TypeScript frontend
├── web-backend/                   # Rust/Axum tracker API
├── windows/pcage-audit/           # Go auditor and reversible hardening CLI
├── windows/Win11Debloat/          # pinned upstream optional customization tool
├── docs/
│   ├── architecture.md
│   ├── security-boundaries.md
│   ├── encrypted-profile-format.md
│   ├── e2ee-sync-protocol.md
│   └── research-notes/
└── tests/                         # cross-module / workflow test material where present
```

## Development and validation

Run checks from the repository root. The commands below describe the expected test gates; do not infer passing results unless the relevant command or CI job has completed.

```sh
# Tracker catalogue and shared Go tools
go -C shared/go/pcage-tools test ./...
go -C shared/go/pcage-tools run . validate-tracker --max-age-days 180

# Android policy/packet core and app tests (JDK 17 + Gradle required)
cd android-app
gradle :android-core:test
gradle :app:testDebugUnitTest
gradle assembleDebug

# Windows Go CLI (run on Windows for platform-specific integration coverage)
cd ../windows/pcage-audit
go test ./...
```

The app-alternative catalogue must also be parsed by the Android validator, with tests covering unknown fields, duplicate IDs, unapproved hosts, non-HTTPS URLs and oversized input. `app-alternatives-report` gates the catalogue-level `updated_at` date and identifies affected entries; schema v1 has no per-entry source-review date, so the report explicitly cannot claim that individual URLs or trade-offs were recently re-checked. The Android VPN requires a separate emulator/physical-device smoke test for IPv4 and IPv6 routing, network transitions, resolver timeouts, service stop/revoke, and normal app connectivity.

Before a release, use the current [research notes](docs/research-notes/privacy-suite-expansion-2026-10-25.md) as a validation checklist. They separate platform-documented capabilities from assumptions and list the device tests still required.

## Security boundaries

- **OEM/system telemetry:** ordinary Android apps cannot disable privileged manufacturer, baseband, firmware or every Google Play Services behavior. A custom ROM changes the trust surface but has its own migration and compatibility costs.
- **Encrypted DNS bypass:** a DNS-only VPN does not inspect arbitrary HTTPS, DoH or DoQ traffic and does not block direct-IP connections.
- **Permission limits:** Android's own settings and package-visibility rules remain in force; iOS is substantially more restrictive.
- **Static scanning:** APK manifest metadata and DEX strings describe potential capability, not proof of execution or collection.
- **Windows policy controls:** allowed registry values and firewall settings are not a kernel filter or guarantee of zero egress. High-impact isolation can render the device temporarily unreachable.
- **Encrypted export:** profile confidentiality is protected, but the portable file does not authenticate a sender. Passphrases should be exchanged separately.
- **Deletion requests:** legal templates can draft and track requests but cannot force or technically verify deletion inside a company's systems.

## Research and contribution

Useful starting points:

- [Architecture](docs/architecture.md)
- [Security boundaries](docs/security-boundaries.md)
- [Permission matrix](docs/permission-matrix.md)
- [Android DNS policy core](android-core/README.md)
- [Tracker database schema](shared/tracker-db/schema.md)
- [Privacy-suite expansion research](docs/research-notes/privacy-suite-expansion-2026-10-25.md)
- [Next 20 engineering milestones](docs/roadmap/next-20-engineering-milestones.md)
- [Next 100 engineering milestones](docs/roadmap/next-100-engineering-milestones.md)
- [Next 100 milestones (121–220)](docs/roadmap/next-100-milestones-121-220.md)
- [Privacy-rights workflow and legal limits](docs/rights-request-workflow.md)
- [iOS companion capability boundary](ios/README.md)
- [Windows privacy hardening research](docs/research-notes/windows-privacy-hardening-2026-10-25.md)

Contributions are welcome for new evidence-backed indicators, SDK signatures, documented OEM behaviors, regression tests, alternative-app reviews and platform validation results. Include authoritative evidence, the date checked, likely false positives, and the precise scope of the claim. New alternatives should include privacy trade-offs, not just a positive description; tracker indicators should not be activated solely because they appeared in an unreviewed feed.

### Research library (25 October 2026)

The expanded research library documents privacy threats, evidence-backed platform boundaries, network observability, APK analysis, data-broker workflows, data minimization, safety considerations, and acceptance tests. Start with [`docs/research/README.md`](docs/research/README.md). The notes distinguish observed signals, static indicators, inference, and unavailable capabilities; they do not imply that planned features are already implemented.

## Security reporting

Do not publish details of an unpatched vulnerability involving user data or security controls in a public issue. Use GitHub's private vulnerability reporting feature if it is enabled for this repository.

## License

MIT. See [LICENSE](LICENSE).
