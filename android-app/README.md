# PrivaCage Android app adapter

This is the first Android platform adapter for the pure Kotlin/JVM DNS core in `../android-core`.

## Implemented

- JPEG metadata inspection report before save, including input/output size and counts of removed APP1 (EXIF/XMP), APP13 (IPTC/Photoshop), and COM segments. A second pass verifies those supported segment classes are absent from the output; other APP markers are preserved and the report does not enumerate every embedded field or guarantee all metadata is gone.
- JPEG input is limited to 100 MiB, staged in private cache, and temporary files are deleted after use or cancellation.

- User-selected APK manifest inspection through Android's package archive parser, staged into a private cache file with a 100 MiB cap, then deleted after inspection.
- Static report with package/version/target-SDK metadata, APK SHA-256, current signing-certificate SHA-256 fingerprints when Android exposes signer metadata, cryptographic APK signature verification through Google's `apksig` library (including supported v1/JAR and v2/v3 schemes), declared permissions with conservative explanations, components the parser reports as exported, and a bounded scan of DEX byte strings for catalog domain/SDK literals.
- Baseline-versus-candidate APK privacy diff, requiring both files to declare the same package. Compares declared permissions, exported components, embedded tracker-catalog indicators, target SDK, signing certificate fingerprints, and signature-verifier results; records both APK SHA-256 values and the exact bundled tracker catalog SHA-256. Each staged APK is deleted after its scan and no APK is uploaded.
- Permission findings are not described as proof of runtime use; the APK is not installed or executed and is not uploaded.
- Local UI for a numeric IPv4 upstream resolver and user-entered blocked domains.
- Optional DNS-over-TLS on port 853 with platform trust, SNI, strict certificate hostname verification, protected sockets, bounded reads, DNS response validation, and no plaintext fallback.
- Android Privacy Dashboard, app-management, location, and Wi-Fi settings shortcuts; these open OS-owned controls rather than claiming to revoke other apps' permissions.
- Bundles the canonical `shared/tracker-db/signatures.json` directly as an Android asset; it does not duplicate the database.
- Displays tracker records with evidence URLs, confidence, review status, and verification dates.
- Lets users explicitly import only `active` domain indicators into the rule editor; changes still require saving. `review` and `retired` records are never imported by this action, and SDK class patterns are informational only.
- Exports and restores the resolver plus domain-rule profile as a passphrase-encrypted `.pcage` file using Argon2id v1.3 and AES-256-GCM. The file is encrypted before being written through Android's document provider.
- Local-only settings in Android SharedPreferences.
- A user-triggered JSON export of the optional local DNS event history, with inclusive date filtering, blocked/forwarded category selection, a redaction preview, and hostname/socket-owner fields excluded by default. Each exported event has a verifiable SHA-256 chain link and the report includes the chain head.
- Signed audit checkpoints wrap the exact export payload hash, event-chain head, record count, creation time, and signer public-key fingerprint with an ECDSA signature from a P-256 private key held by Android Keystore. The local verifier checks the signature, exact payload bytes, event chain, and whether the signer key matches the key currently stored by this installation. Exports remain plaintext JSON.
- A user-triggered JSON export of the optional local DNS event history, with inclusive date filtering, blocked/forwarded category selection, a redaction preview, and hostname/socket-owner fields excluded by default. The Android system save picker is used; exports are plaintext JSON.
- Preflight disclosure before Android VPN consent, including the possibility of replacing the currently active VPN, the chosen upstream DNS transport, and the supported routing scope.
- A local VPN lifecycle status panel that follows service start, establishment, shutdown, revocation, and errors. Active/starting status from a previous app process is treated as stale rather than live.
- A user-triggered DNS route diagnostic that sends one fixed `example.com` A query through the configured upstream transport, protected from VPN routing and using the configured DNS-over-TLS certificate checks when enabled.
- Before/after snapshots of Android-visible non-VPN networks, recording only transport category, Android validation/captive-portal state, and the number of DNS servers exposed; no network IDs, IP addresses, SSIDs, or DNS server addresses are recorded by this snapshot.
- The probe result distinguishes a valid resolver response from a successful name resolution, records elapsed time and DNS response code, and does not add its hostname to local DNS event history.
- Explicit `VpnService.prepare()` consent.
- A `VpnService` with a virtual DNS address and a route only to that address.
- A blocking TUN read/write loop that processes supported IPv4 UDP DNS packets and returns responses.
- Protected upstream UDP and TCP sockets using `VpnService.protect`; upstream TCP is retried when a valid UDP response sets the DNS TC flag.
- A foreground notification and explicit handling of tunnel I/O/processing errors.
- A failed upstream query is dropped without intentionally shutting down the whole VPN tunnel.

## Build

Requires JDK 17, Android SDK platform 36, and Gradle 8.14 or compatible.

    gradle assembleDebug
    gradle :android-core:test
    gradle :app:testDebugUnitTest

The debug APK is generated at `app/build/outputs/apk/debug/app-debug.apk`.

## Limits

- A signed checkpoint detects changes to the exported snapshot but cannot prove that unrecorded events never occurred, that the device clock is correct, or that the signer is a particular person. The public-key fingerprint must be trusted independently. Android Keystore hardware backing is device-dependent. Deleting or losing the signing key can leave old checkpoints cryptographically verifiable but no longer anchored to this installation. Checkpoint JSON is not encrypted.
- Checkpoint signing and verification are bounded to 2 MiB per envelope, 1 MiB per embedded payload and 100 events. The verifier rejects unsupported fields, inconsistent counters/dates, false redaction claims and non-P-256 signer keys. The portable Rust verifier is the cross-device offline verification path; embedded keys still require an independent trust decision.
- Audit export covers only the retained optional DNS event history (maximum 100 events); it does not synthesize a complete device audit log or export aggregate counters as time-ranged records. Hostnames and best-effort socket-owner labels are redacted by default; selecting them includes sensitive data. JSON exports are not encrypted, and the selected destination may sync to a provider. Malformed timestamps or unsupported categories are counted; unreadable stored JSON cancels the export rather than being silently treated as an empty log.
- APK inspection and comparison are static: the diff compares manifest declarations, exported components, bounded DEX literal matches, target SDK, and signing metadata for two user-selected APKs with the same package ID. It records both APK hashes and the bundled tracker-catalog hash, but does not decompile or analyze every code path, verify permission grants, prove network activity, or decide that an app is malicious. A valid signature proves integrity relative to the included signing certificate, not publisher identity or safety. Marker strings may be unused, dead code, test data, or embedded documentation; a missing marker is not proof the behavior was removed.
- The APK is user-selected, limited to 100 MiB, copied into private cache for parsing, and deleted after inspection; no APK upload or installation occurs.
- The bundled catalog currently contains only two Analytics endpoint indicators and is not comprehensive. Only explicitly imported active domain indicators (plus manually entered domains) become blocking rules; review-status records are excluded.
- The client-facing tunnel supports IPv4 UDP DNS only. It does not accept DNS-over-TCP connections from device apps.
- Plain DNS mode uses ordinary UDP/TCP and remains unencrypted. Optional DNS-over-TLS encrypts only device-to-resolver DNS; the resolver can still observe queries, and DoH/DoQ or IPv6 paths are not filtered. TLS failure drops the query rather than falling back to plaintext. Encrypted backups include the selected transport and TLS hostname, but do not provide account/device sync.
- Privacy settings shortcuts do not give PrivaCage OS privileges. Android itself, privileged system components, device-management software, and OEM services remain outside an ordinary app's control.
- If a complete TCP response is too large to fit into the client-facing UDP packet, the query fails rather than producing a fabricated answer.
- Queries are processed sequentially; a slow resolver delays later requests.
- The service does not attribute queries to apps or inspect HTTPS contents.
- IPv6 DNS, DoH, DoT, and DoQ are not filtered.
- The encrypted `.pcage` file uses the format documented in `docs/encrypted-profile-format.md`. Anyone who receives both the file and passphrase can read its contents; share the passphrase through a separate trusted channel.
- This code has not been tested on an emulator or physical device. CI and device validation are required before calling it release-ready.
- Catalog parsing is strict and fails visibly in the UI if its schema is invalid; manual rules remain usable. The catalog is bundled at build time, not remotely updated.
- Platform/device policy can prevent VPN or foreground-service startup. Failures stop the service; DNS query names are not logged.
- The lifecycle panel reports PrivaCage's recorded service state, not a DNS leak test. It cannot prove all apps use the virtual DNS endpoint, and it does not cover IPv6 DNS, DNS-over-TCP from apps, DNS-over-HTTPS, DNS-over-QUIC, or HTTPS payloads.
- DNS route diagnostics are an explicit one-query test of the configured resolver path, not a comprehensive leak test. The response demonstrates only that a matching DNS response came back through that transport at the time tested. Android network capability snapshots can identify a system-detected captive portal or lack of validation but do not prove which route every app uses. Wi-Fi-to-mobile handovers and captive-portal behavior still need emulator/physical-device testing.

- JPEG scrubber limits: JPEG only; APP1, APP13, and COM markers are removed. Other APP markers remain, so vendor-specific metadata may survive. Files with trailing data after EOI are rejected.

- Roster-owner key rotation uses a dual-signed transition from the current and replacement owner keys, bound to the relay space and exact next roster revision. Import also requires the full replacement fingerprint to be independently confirmed out of band and the next roster to verify. The replacement private bundle stays in the Android Keystore-protected local record; only the signed transition and public roster are exported. The public handoff package is retained in the protected local record for re-copying, and further owner rotation or recovery replacement/export is blocked until the user acknowledges that every intended peer accepted the new owner and roster. That acknowledgement cannot be independently proven by this client. Relay member credentials may need separate administrator replacement, and a lost old owner key cannot perform this continuity-preserving rotation.
