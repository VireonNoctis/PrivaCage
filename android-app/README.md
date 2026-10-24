# PrivaCage Android app adapter

This is the first Android platform adapter for the pure Kotlin/JVM DNS core in `../android-core`.

## Implemented

- JPEG metadata removal for a user-selected local image. The streaming parser removes APP1 (EXIF/XMP), APP13 (IPTC/Photoshop), and COM segments without recompressing pixels; the cleaned file is saved only to a user-selected destination.
- JPEG input is limited to 100 MiB, staged in private cache, and temporary files are deleted after use or cancellation.

- User-selected APK manifest inspection through Android's package archive parser, staged into a private cache file with a 100 MiB cap, then deleted after inspection.
- Static report with package/version/target-SDK metadata, APK SHA-256, current signing-certificate SHA-256 fingerprints when Android exposes signer metadata, cryptographic APK signature verification through Google's `apksig` library (including supported v1/JAR and v2/v3 schemes), declared permissions with conservative explanations, components the parser reports as exported, and a bounded scan of DEX byte strings for catalog domain/SDK literals.
- Permission findings are not described as proof of runtime use; the APK is not installed or executed and is not uploaded.
- Local UI for a numeric IPv4 upstream resolver and user-entered blocked domains.
- Optional DNS-over-TLS on port 853 with platform trust, SNI, strict certificate hostname verification, protected sockets, bounded reads, DNS response validation, and no plaintext fallback.
- Android Privacy Dashboard, app-management, location, and Wi-Fi settings shortcuts; these open OS-owned controls rather than claiming to revoke other apps' permissions.
- Bundles the canonical `shared/tracker-db/signatures.json` directly as an Android asset; it does not duplicate the database.
- Displays tracker records with evidence URLs, confidence, review status, and verification dates.
- Lets users explicitly import only `active` domain indicators into the rule editor; changes still require saving. `review` and `retired` records are never imported by this action, and SDK class patterns are informational only.
- Exports and restores the resolver plus domain-rule profile as a passphrase-encrypted `.pcage` file using Argon2id v1.3 and AES-256-GCM. The file is encrypted before being written through Android's document provider.
- Local-only settings in Android SharedPreferences.
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

The debug APK is generated at `app/build/outputs/apk/debug/app-debug.apk`.

## Limits

- APK inspection is static: it reports manifest declarations, current signer certificate SHA-256 fingerprints when available, verifies APK signature integrity with Google's `apksig` library, and searches bounded DEX data for literal catalog markers. A valid signature proves integrity relative to the included signing certificate, not publisher identity or safety. It does not decompile or analyze every code path, verify permission grants, prove network activity, or decide that an app is malicious. Marker strings may be unused, dead code, test data, or embedded documentation.
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

- JPEG scrubber limits: JPEG only; APP1, APP13, and COM markers are removed. Other APP markers remain, so vendor-specific metadata may survive. Files with trailing data after EOI are rejected.
