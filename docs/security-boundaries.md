# Security boundaries and verification status

This document is a claim boundary for PrivaCage. A capability is not treated as implemented just because an API, design sketch, or roadmap item exists.

## Implemented in the current branch

| Area | Evidence-backed claim | Boundary |
|---|---|---|
| PCAGE01 encrypted profile envelope | Kotlin/JVM and Rust can decrypt the same checked-in known-answer vector. Production encryption uses Argon2id v1.3 and AES-256-GCM with fresh OS-generated salt and nonce. | The vector checks interoperability for one fixture; it is not a cryptographic audit. |
| Rust profile payload | The Rust API validates JSON shape, version, numeric IPv4 resolver, normalized domains, duplicates, and size limits before returning a typed profile. | Calling code must still validate before applying imported settings. |
| Tracker signature catalog | The canonical JSON schema and basic evidence URL structure are checked by CI. CI also rejects evidence review dates older than 180 days, which forces re-review but does not prove source truth or availability. New catalog records include source URLs and evidence descriptions. | Schema validation does not prove that a source is accurate, current, or independent. The current dataset is a small starter set. |
| Android backup declaration | CI verifies that the source manifest explicitly sets `android:allowBackup="false"`. | This is a static configuration check, not proof of behavior across every Android release, OEM migration path, or device-to-device transfer. Device tests are still required. |
| APK static audit | The user-selected APK is parsed locally for requested permissions, version/target-SDK metadata, SHA-256, exported components, and bounded literal-marker searches in DEX byte strings; the temporary copy is deleted after inspection. | Does not install or execute the file. String matches are possible embedded indicators, not proof of a loaded SDK, live network traffic, permission grants, data collection, or malicious intent. Coverage caps and obfuscation/native code can produce missed indicators. |
| Android DNS policy core | The local core evaluates configured domain rules and handles the documented IPv4 UDP DNS path with upstream UDP/TCP fallback for truncated responses. An offline preview uses the same suffix-matching function, and aggregate counters record blocked/forwarded/unsupported/upstream-failure outcomes without query names. | Counters describe core outcomes, not successful delivery to apps. The VPN adapter is early implementation and has not been release-validated on a representative device matrix. |

## Explicitly not implemented or not established

- **No encrypted sync service.** There is no account service, multi-device key exchange, authenticated sender identity, membership/revocation model, key recovery, replay prevention, or conflict resolution. A password-encrypted export file must not be called a complete end-to-end encrypted synchronization system.
- **No live DNS encryption in the current forwarder.** The configured upstream uses UDP/TCP DNS. The local VPN tunnel does not itself encrypt the device-to-resolver path. Strict DNS-over-TLS/HTTPS with authenticated resolver identity remains future work.
- **DNS counters are aggregate only.** They do not retain queried hostnames or packet contents. They count DNS-core decisions/responses prepared and do not establish that Android delivered every response to its requesting application.
- **No universal traffic visibility.** The current Android path handles IPv4 UDP DNS only. It does not prove coverage of IPv6, DoH, DoT, DoQ, direct-to-IP traffic, apps using their own encrypted resolver, or traffic from other LAN devices.
- **No universal app attribution.** A hostname match does not prove which app initiated a request unless the platform supplies reliable attribution. Static APK findings indicate possible capability or embedded indicators, not runtime execution.
- **No dynamic APK analysis.** The initial APK manifest audit reports declarations and exported component metadata only. It does not establish permission grants, inspect every code path, or prove that a capability was used.
- **No generic permission shim on stock devices.** An ordinary Android app cannot freely revoke every other app's permissions or intercept every sensor/API call. iOS cannot inspect other apps' binaries or override their permissions outside approved system APIs and entitlements.
- **No claim of encrypted local preferences.** PCAGE export encryption does not imply that all on-device settings, logs, caches, or crash artifacts are encrypted at rest.
- **No claim that an imported signature is unquestionably malicious.** Active records are sourced indicators with known service semantics; broad/shared endpoints remain review-only where blocking could break unrelated functionality.
- **No metadata scrubber yet.** Metadata inspection/scrubbing is a research candidate, not an implemented feature. Any future scrubber must validate the sanitized copy; removing known EXIF fields cannot remove identifying visual content or cover unsupported formats.
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
