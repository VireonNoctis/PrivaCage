# Security boundaries and verification status

This document is a claim boundary for PrivaCage. A capability is not treated as implemented just because an API, design sketch, or roadmap item exists.

## Implemented in the current branch

| Area | Evidence-backed claim | Boundary |
|---|---|---|
| PCAGE01 encrypted profile envelope | Kotlin/JVM and Rust can decrypt the same checked-in known-answer vector. Production encryption uses Argon2id v1.3 and AES-256-GCM with fresh OS-generated salt and nonce. | The vector checks interoperability for one fixture; it is not a cryptographic audit. |
| Rust profile payload | The Rust API validates JSON shape, version, numeric IPv4 resolver, normalized domains, duplicates, and size limits before returning a typed profile. | Calling code must still validate before applying imported settings. |
| Tracker signature catalog | The canonical JSON schema and basic evidence URL structure are checked by CI. CI also rejects evidence review dates older than 180 days, which forces re-review but does not prove source truth or availability. New catalog records include source URLs and evidence descriptions. | Schema validation does not prove that a source is accurate, current, or independent. The current dataset has fifteen curated records and remains a small starter set. A review-report script calculates current, due-soon, overdue, and invalid-future-date states; CI still gates evidence dates at 180 days. |
| Android backup declaration | CI verifies that the source manifest explicitly sets `android:allowBackup="false"`. | This is a static configuration check, not proof of behavior across every Android release, OEM migration path, or device-to-device transfer. Device tests are still required. |
| APK static audit | The user-selected APK is parsed locally for requested permissions, version/target-SDK metadata, APK SHA-256, current signing-certificate SHA-256 fingerprints, exported components, and bounded DEX literal-marker searches. Android uses Google's `apksig` verifier to check APK signature integrity across supported signing schemes; malformed/invalid and verification-error states are reported separately. The temporary copy is deleted after inspection. | A valid signature proves integrity relative to the included signing certificate, not publisher identity or safety. The Rust CLI still only extracts v2/v3 certificate fingerprints and does not verify signatures. Static declarations and strings are not proof of runtime behavior; coverage caps, obfuscation, native code, and unsupported archive formats can cause missed indicators. |
| Android DNS policy core | The local core evaluates configured domain rules and handles the documented IPv4 UDP DNS path with upstream UDP/TCP fallback for truncated responses. Optional DNS-over-TLS uses certificate hostname verification and fails closed instead of falling back to plaintext. A local device snapshot reports exposed location, Wi-Fi, Private DNS, and active-default-network VPN settings; a separate local audit reports declared dangerous permissions and grant flags for launcher-visible apps. An opt-in, bounded local DNS event history records hostname, decision, timestamp, and best-effort socket-owner information. | Counters describe core outcomes, not successful delivery to apps. The VPN adapter is early implementation and has not been release-validated on a representative device matrix. Package visibility omits some packages, and neither audit can identify all privileged OS/OEM collection. |

## Explicitly not implemented or not established

- **E2EE sync is an early Android client + protocol + relay integration, not a complete sync product.** The shared Rust core provides per-device Ed25519/X25519 identities, recipient-bound signed ciphertext, durable replay protection, signed key rotation, and passphrase-encrypted identity recovery. Android calls the Rust core through JNI, protects its local record and relay capability with an AES-GCM key from Android Keystore, requires explicit out-of-band fingerprint confirmation before trusting a peer, sends profiles through an HTTPS-only relay client, and stages a verified profile in protected local storage for user approval before applying. Regression tests cover Rust protocol/relay round-tripping and HTTPS configuration validation. There is no iOS/Windows client, account service, signed group roster/revocation, conflict resolution, per-device relay revocation, independent cryptographic audit, or representative physical-device lifecycle validation. The relay listener remains loopback-only and requires a correctly configured TLS reverse proxy for remote use.
- **DNS encryption is optional and scoped.** When explicitly enabled, the configured upstream uses DNS-over-TLS with certificate hostname verification and no plaintext fallback. When disabled, upstream DNS uses UDP/TCP. The feature covers only the supported DNS path; it does not encrypt arbitrary device traffic or hide queries from the chosen resolver.
- **DNS counters are aggregate only; optional event history is separate.** Aggregate counters retain no queried hostnames. A user can explicitly enable a bounded local history that stores hostnames, decisions, timestamps, and best-effort socket-owner labels on-device; recording is off by default and the user can clear it. Socket-owner lookup may be unavailable or identify Android's system resolver, not the originating app. No history is uploaded by this feature.
- **No universal traffic visibility.** The current Android path handles IPv4 UDP DNS only. It does not prove coverage of IPv6, DoH, DoT, DoQ, direct-to-IP traffic, apps using their own encrypted resolver, or traffic from other LAN devices.
- **No full-device VPN lockdown yet.** The current VPN routes only the configured virtual DNS endpoint, not all device traffic. Do not enable Android's “Block connections without VPN” with PrivaCage as the selected VPN; ordinary app traffic may be blocked. The app links to VPN settings only with an explicit warning.
- **No universal app attribution.** The event history attempts Android 10+ UDP socket-owner lookup when available, but this is not reliable proof of the app that initiated a DNS lookup: Android's system resolver may own the socket, and lookup may fail. A hostname match alone does not identify an app. Static APK findings indicate possible capability or embedded indicators, not runtime execution. The launcher-visible permission audit reports manifest declarations and current grant flags only; package visibility means it is not a complete system/OEM inventory.
- **No dynamic APK analysis.** APK signature integrity is now verified by the Android adapter using `apksig`, but the audit still does not install or execute the APK, establish permission grants, inspect every code path, or prove that a capability was used. The Rust CLI's v2/v3 certificate extraction remains metadata-only and is not a signature verifier.
- **No generic permission shim on stock devices.** An ordinary Android app cannot freely revoke every other app's permissions or intercept every sensor/API call. iOS cannot inspect other apps' binaries or override their permissions outside approved system APIs and entitlements.
- **No claim of encrypted local preferences.** PCAGE export encryption does not imply that all on-device settings, logs, caches, or crash artifacts are encrypted at rest.
- **No claim that an imported signature is unquestionably malicious.** Active records are sourced indicators with known service semantics; broad/shared endpoints remain review-only where blocking could break unrelated functionality.
- **JPEG metadata removal is limited.** The local parser strips APP1 (EXIF/XMP), APP13 (IPTC/Photoshop), and COM segments without re-encoding pixel data. Before save, the app reports input/output sizes and counts by supported segment class; a second pass verifies those classes are absent from the output. Other APP segments remain, the report does not enumerate every embedded field, and this is not a guarantee that every metadata type is removed from every JPEG. Files with trailing data after EOI are rejected.
- **No legal request automation yet.** The legal request assistant is planned, not established as implemented by this branch. Even after it is built, a submitted request will not prove that a company or downstream recipient erased the data.

## Required checks

Run from the repository root:

```sh
python shared/scripts/validate-signatures.py
python shared/scripts/validate-android-backup.py
python -m unittest discover -s tests -v
cargo fmt --manifest-path shared/rust/pcage-crypto/Cargo.toml --all -- --check
cargo test --manifest-path shared/rust/pcage-crypto/Cargo.toml
cargo clippy --manifest-path shared/rust/pcage-crypto/Cargo.toml --all-targets -- -D warnings
```

A green static check is evidence only for the invariant it tests. It does not replace Android emulator/device tests, iOS entitlement approval, independent cryptographic review, or a real interoperability test across every shipping implementation.

## Security change gate

1. New tracker signatures require evidence that supports the exact indicator and a human review of collateral blocking risk.
2. New profile format versions require a new explicit version/magic, updated format documentation, and shared interoperability vectors. Never change KDF parameters silently.
3. Any future catalog updater must authenticate update metadata and resist rollback; HTTPS and a schema-valid JSON file alone are insufficient protection against a compromised publisher account or repository.
4. Any future sync protocol must establish peer/device identity, key lifecycle and revocation, replay/conflict handling, recovery semantics, and metadata exposure before claiming end-to-end encryption.
5. Any new diagnostic must report failed or unobservable paths explicitly. A missing observation is not evidence that no tracking occurred.


| JPEG metadata removal | The local parser strips APP1 (EXIF/XMP), APP13 (IPTC/Photoshop), and COM segments without re-encoding pixel data. | Other APP segments remain, so this is not a guarantee that every metadata type is removed from every JPEG. Files with trailing data after EOI are rejected. |
