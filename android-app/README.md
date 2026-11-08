# PrivaCage Android app adapter

This is the first Android platform adapter for the pure Kotlin/JVM DNS core in `../android-core`.

## Implemented

- Image metadata inspection and scrubbing for JPEG, PNG, and WebP, with input/output size and counts for the supported metadata classes. JPEG reports APP1 (EXIF/XMP-class), APP13 (IPTC/Photoshop), and comments; PNG reports recognized EXIF, text/XMP, timestamp, and physical-resolution chunks; WebP reports recognized EXIF and XMP chunks. A second pass verifies the recognized metadata classes were removed from the separate output. This is not a guarantee that every possible metadata field or visible privacy clue is removed.
- Image inputs are limited to 100 MiB and staged in private cache; temporary files are deleted after use or cancellation.

- User-selected APK manifest inspection through Android's package archive parser, staged into a private cache file with a 100 MiB cap, then deleted after inspection.
- Static report with package/version/target-SDK metadata, APK SHA-256, current signer fingerprints, Android-provided signing-certificate history for single-signer packages on API 28+, cryptographic APK signature verification through Google's `apksig` library (including supported v1/JAR and v2/v3 schemes), declared permissions with conservative explanations, components the parser reports as exported, and a bounded scan of DEX byte strings for catalog domain/SDK literals.
- Baseline-versus-candidate APK privacy diff, requiring both files to declare the same package. Compares declared permissions, exported components, embedded tracker-catalog indicators, target SDK, signer continuity (including platform-recognized rotation, multiple-signer set changes, possible downgrade and unknown lineage), and signature-verifier results; records both APK SHA-256 values and the exact bundled tracker catalog SHA-256. Each staged APK is deleted after its scan and no APK is uploaded.
- Permission findings are not described as proof of runtime use; the APK is not installed or executed and is not uploaded.
- Local UI for a numeric IPv4 upstream resolver and user-entered blocked domains.
- Optional DNS-over-TLS on port 853 with platform trust, SNI, strict certificate hostname verification, protected sockets, bounded reads, DNS response validation, and no plaintext fallback.
- Android Privacy Dashboard, app-management, location, and Wi-Fi settings shortcuts; these open OS-owned controls rather than claiming to revoke other apps' permissions.
- Bundles the canonical `shared/tracker-db/signatures.json` directly as an Android asset; it does not duplicate the database.
- Displays tracker records with evidence URLs, confidence, review status, and verification dates.
- Lets users explicitly import only `active` domain indicators into the rule editor; changes still require saving. `review` and `retired` records are never imported by this action, and SDK class patterns are informational only.
- Exports and restores the resolver plus domain-rule profile as a passphrase-encrypted `.pcage` file using Argon2id v1.3 and AES-256-GCM. The file is encrypted before being written through Android's document provider.
- Local aggregate DNS counters and operational/lifecycle preferences in app-private SharedPreferences. These non-secret operational values are not all separately AES-GCM encrypted.
- Local permission-audit comparisons retain a schema-v2 snapshot with the device-clock capture timestamp. Legacy schema-v1 baselines remain readable and are upgraded after the next complete scan. Encoding is bounded to 4 MiB, 2,000 launcher-visible packages, and 256 dangerous permissions per package; an incomplete or over-limit scan does not replace the previous baseline.
- A user-triggered JSON export of the optional local DNS event history, with inclusive date filtering, blocked/forwarded category selection, a redaction preview, and hostname/socket-owner fields excluded by default. Each exported event has a verifiable SHA-256 chain link and the report includes the chain head.
- Signed audit checkpoints wrap the exact export payload hash, event-chain head, record count, creation time, and signer public-key fingerprint with an ECDSA signature from a P-256 private key held by Android Keystore. The local verifier checks the signature, exact payload bytes, event chain, and whether the signer key matches the key currently stored by this installation. Exports remain plaintext JSON.
- A user-triggered JSON export of the optional local DNS event history, with inclusive date filtering, blocked/forwarded category selection, a redaction preview, and hostname/socket-owner fields excluded by default. The Android system save picker is used; exports are plaintext JSON.
- Preflight disclosure before Android VPN consent, including the possibility of replacing the currently active VPN, the chosen upstream DNS transport, and the supported routing scope.
- A local VPN lifecycle status panel that follows service start, establishment, shutdown, revocation, and errors. Active/starting status from a previous app process is treated as stale rather than live.
- A user-triggered DNS route diagnostic that sends one fixed `example.com` A query through the configured upstream transport, protected from VPN routing and using the configured DNS-over-TLS certificate checks when enabled.
- Before/after snapshots of Android-visible non-VPN networks, recording only transport category, Android validation/captive-portal state, and the number of DNS servers exposed; no network IDs, IP addresses, SSIDs, or DNS server addresses are recorded by this snapshot.
- The probe result distinguishes a valid resolver response from a successful name resolution, records elapsed time and DNS response code, and does not add its hostname to local DNS event history.
- Explicit `VpnService.prepare()` consent.
- A `VpnService` with separate virtual IPv4 and IPv6 DNS endpoints and routes limited to those endpoints; general IP traffic is not routed through this tunnel.
- A blocking TUN read/write loop that processes supported IPv4 and constrained IPv6 UDP-DNS packets and returns responses.
- Protected upstream UDP and TCP sockets using `VpnService.protect`; upstream TCP is retried when a valid UDP response sets the DNS TC flag.
- A foreground notification and explicit handling of tunnel I/O/processing errors.
- A failed upstream query is dropped without intentionally shutting down the whole VPN tunnel.

## Local app policy review

The queue stores launcher-visible package IDs, install/open trigger times and user-supplied HTTPS policy links in its own Android Keystore-encrypted file. New launcher-visible apps are detected on the next PrivaCage foreground/resume. A scan fails closed and preserves the existing queue if Android omits PrivaCage's own launcher entry or returns no other launcher-visible packages; an empty result is never treated as evidence that every app was uninstalled. App-open detection requires the user to grant Android's special Usage Access setting. PrivaCage displays a prompt when the user returns to PrivaCage; it does not overlay other apps. Non-launcher apps and packages hidden by Android package visibility may be missed. The user opens supplied policy URLs in the system browser and records review status; PrivaCage does not fetch, crawl, store or upload policy text.

## Local encryption and strict no-telemetry


The Android build now encrypts the DNS resolver/domain/DoT configuration, rights-request tracker metadata, and permission-audit comparison baseline in separate AES-256-GCM preference envelopes using separate Android Keystore keys and purpose-bound AAD. The app validates the complete legacy value before migrating it; it removes the legacy plaintext keys only after an encrypted replacement has been synchronously committed. A missing key or authentication failure is an error and preserves existing ciphertext rather than silently creating a new key.

Other sensitive stores already use their own encryption paths: local DNS history, the app-policy review queue, and sync identity. Aggregate counters, lifecycle/status and other non-secret operational preferences remain ordinary app-private preferences. They are not uploaded by PrivaCage, but not every preference is encrypted. Signed audit checkpoint exports are plaintext JSON unless the user separately protects the destination.

The Android client has a strict no-product-telemetry policy. CI scans the manifest, Gradle files and main application source for known analytics, attribution, advertising and remote crash-reporting SDK/advertising-ID markers. The check cannot prove the absence of every unknown SDK, custom telemetry implementation, Android/OEM diagnostic, system log or network-provider log. User-configured DNS, externally opened policy links and configured encrypted sync are functional network requests and are not telemetry.

The six policy documents under `docs/privacy/` are bundled as Android assets. The Legal & Privacy screen reads them locally without contacting a policy server. They remain draft documents until the responsible controller details, contact address, lawful bases, service operators and effective date are completed and legally reviewed.


For the privacy-policy asset and no-telemetry regression tests, run from the repository root:

```sh
go -C shared/go/pcage-tools test ./...
```

The Android CI workflow also runs `:app:testDebugUnitTest` and builds the debug APK; a successful Go validator test alone is not an Android build result.

## Build

Requires JDK 17, Android SDK platform 36, and Gradle 8.14 or compatible.

    gradle assembleDebug
    gradle :android-core:test
    gradle :app:testDebugUnitTest

The debug APK is generated at `app/build/outputs/apk/debug/app-debug.apk`.


## Monitoring-access review (stock Android)

The user-triggered Monitoring Access Review reads four narrowly scoped Android surfaces:

- AccessibilityManager returns enabled accessibility services for FEEDBACK_ALL_MASK.
- DevicePolicyManager.getActiveAdmins() returns active device-administrator components for the current user/profile.
- The AOSP-defined `enabled_notification_listeners` secure-setting value can list notification-listener components. Its key is hidden/deprecated in AOSP and is not a stable public SDK contract; the screen never reads notification contents. A missing (`null`) value is shown as unavailable because it cannot prove that no listeners are enabled; an explicit empty value is the only successful empty result.
- ConnectivityManager reports whether the current default network has NetworkCapabilities.TRANSPORT_VPN. This does not identify the VPN owner or describe other/non-default routes.

The review runs only after the user taps its button. It uses the existing ACCESS_NETWORK_STATE permission for the network-capability check; it adds no permission, package-visibility query, Usage Access dependency, notification, background service, network request, persistence, or upload. Component-setting input is bounded to 16 KiB and 100 entries. Malformed, oversized, truncated, or missing values are shown as partial/unavailable rather than as an empty list. The notification-listener observation is best-effort because its AOSP setting key is not a stable public SDK contract. For each reported component package, a separate explicit action can open Android's app-info page with ACTION_APPLICATION_DETAILS_SETTINGS; this does not query installed-app labels or change access and safely reports when the device does not expose the handoff.

A listed service may be legitimate assistive technology, automation, password management, notification sync, work/school management, or a VPN. The result is direct evidence of an OS-reported setting, not evidence of intent, misuse, or a person's involvement. The VPN check covers only the active default network and does not identify the owning app. No root/system-only indicators are collected. No result is saved; leaving the screen discards the displayed snapshot.

Official API behavior was reviewed on 7 November 2026; see docs/research/SOURCES.md. Physical-device/OEM behavior and the safety interaction still require validation before release.

## Experimental cellular downgrade warning

The Android app builds as **0.2.0-experimental**. While the main activity is resumed, an Android 12+ TelephonyCallback.DisplayInfoListener reports the packet-data network type for the default subscription. GPRS, EDGE and GSM are shown as a high-priority 2G warning; CDMA/1xRTT/iDEN are labelled separately as legacy 2G-class technologies. Unknown and unsupported results remain explicitly unknown.

This is only a radio-generation indicator. TelephonyDisplayInfo.getNetworkType() reports the packet-switched network type; it does not expose cellular cipher/encryption state, prove a false base station, inspect voice-only service, or cover every SIM. OEM/carrier presentation behavior requires physical-device validation.

Users get Settings handoffs to review 2G protection for each SIM and Android's unencrypted-network notifications. Android 12+ can disable 2G at the radio layer on supported modems; Android 14+ programmatic changes require privileged phone-state authority. Android 16's native unencrypted-network and identifier-disclosure alerts require compatible modem APIs and are off by default. PrivaCage does not attempt to change either setting.

The monitor unregisters when the activity pauses. It adds no Accessibility Service, phone-state permission, location permission, cell scan, background worker, notification, network request, or persistent radio history. Accessibility access is unrelated to cellular cipher/radio enforcement and is not requested.

## Cellular security onboarding checklist

The main screen opens a dedicated checklist. Its per-SIM 2G protection, Android 16 unencrypted-network alert, system-update, USB-debugging and Play Protect states are explicitly **user-reported**. Each row has three choices: not reviewed, user confirmed, or unavailable/could not verify. Selections are saved in a small AES-256-GCM envelope using a dedicated Android Keystore key. If the saved value cannot be authenticated or validated, the UI preserves it and disables edits rather than replacing it with an empty checklist.

Two separate device signals are read directly: KeyguardManager.isDeviceSecure() reports whether Android has a secure lock credential configured, and Build.VERSION.SECURITY_PATCH reports Android's visible security patch date. Neither is a security verdict. The patch date is not a complete vendor/modem freshness check; the lock signal does not measure credential strength.

The checklist also offers manual reviews for Android Theft Protection and Advanced Protection/USB Protection. Theft Protection controls (Theft Detection Lock, Offline Device Lock, Failed Authentication Lock, Identity Check and Remote Lock) are model/region dependent. Remote Lock requires a screen lock, active SIM, verified number, Find Hub and connectivity. Android 16 Advanced Protection Mode is an opt-in bundle; Intrusion Logging is optional. USB Protection is documented for Pixel 6 and later and blocks new USB data connections while the screen is locked. These are user-confirmed reports, not app-read settings.

The checklist schema is now version 2. Existing encrypted schema-v1 records are validated and migrated by retaining their five existing choices and setting the two new items to `NOT_REVIEWED`; the migrated value is written through the same encrypted Keystore vault. A failed migration preserves the original encrypted record.

The checklist does not request Accessibility, phone-state, cell-location, location, package-inventory, Advanced Protection status or new runtime permissions. It does not read ADB state (Android specifies that the public global setting reads as zero for all third-party apps), bootloader state, all-SIM radio state, Play Protect status, Theft Protection state, Advanced Protection state, USB Protection state or carrier SIM-port settings. Settings handoffs remain user-controlled.

## Limits

- A signed checkpoint detects changes to the exported snapshot but cannot prove that unrecorded events never occurred, that the device clock is correct, or that the signer is a particular person. The public-key fingerprint must be trusted independently. Android Keystore hardware backing is device-dependent. Deleting or losing the signing key can leave old checkpoints cryptographically verifiable but no longer anchored to this installation. Checkpoint JSON is not encrypted.
- Checkpoint signing and verification are bounded to 2 MiB per envelope, 1 MiB per embedded payload and 100 events. The verifier rejects unsupported fields, inconsistent counters/dates, false redaction claims and non-P-256 signer keys. The portable Rust verifier is the cross-device offline verification path; embedded keys still require an independent trust decision.
- Audit export covers only the retained optional DNS event history (maximum 100 events); it does not synthesize a complete device audit log or export aggregate counters as time-ranged records. Hostnames and best-effort socket-owner labels are redacted by default; selecting them includes sensitive data. JSON exports are not encrypted, and the selected destination may sync to a provider. Malformed timestamps or unsupported categories are counted; unreadable stored JSON cancels the export rather than being silently treated as an empty log.
- APK inspection and comparison are static: the diff compares manifest declarations, exported components, bounded DEX literal matches, target SDK, and signing metadata for two user-selected APKs with the same package ID. On API 28+, Android's `SigningInfo` exposes the ordered proof-of-rotation history for a single signer; multiple simultaneous signers are compared as a complete unordered set and do not have a rotation history. Below API 28, or when signer metadata is absent, lineage is marked unavailable rather than inferred. The history comparison distinguishes a forward lineage extension from a mismatch, lineage regression, or possible lower-version downgrade; it is not a publisher identity or safety verdict. The report records both APK hashes and the bundled tracker-catalog hash, but does not decompile or analyze every code path, verify permission grants, prove network activity, or decide that an app is malicious. A valid signature proves integrity relative to the included signing certificate, not publisher identity or safety. Marker strings may be unused, dead code, test data, or embedded documentation; a missing marker is not proof the behavior was removed.
- The APK is user-selected, limited to 100 MiB, copied into private cache for parsing, and deleted after inspection; no APK upload or installation occurs.
- The bundled catalog currently contains only two Analytics endpoint indicators and is not comprehensive. Only explicitly imported active domain indicators (plus manually entered domains) become blocking rules; review-status records are excluded.
- The client-facing tunnel supports IPv4 UDP DNS and a constrained IPv6 UDP-DNS format. It does not accept DNS-over-TCP connections initiated by device apps. IPv6 extension headers, fragments, and jumbograms are rejected; responses that exceed the TUN MTU are dropped rather than silently truncated.
- Plain upstream DNS is unencrypted. Optional DNS-over-TLS encrypts only DNS requests PrivaCage sends to its configured resolver; that resolver can still observe query names. TLS certificate/hostname failure drops the query instead of falling back to plaintext. The tunnel does not intercept app-owned DNS-over-HTTPS, DNS-over-QUIC, arbitrary DNS-over-TLS endpoints, direct-IP connections, or general IPv6 traffic; IPv6 handling is limited to the virtual DNS endpoint. Encrypted backups include the selected upstream transport and TLS hostname, but do not provide account/device sync.
- Privacy settings shortcuts do not give PrivaCage OS privileges. Android itself, privileged system components, device-management software, and OEM services remain outside an ordinary app's control.
- If a complete TCP response is too large to fit into the client-facing UDP packet, the query fails rather than producing a fabricated answer.
- Queries are processed sequentially; a slow resolver delays later requests.
- The service does not attribute queries to apps or inspect HTTPS contents.
- App-owned DoH/DoQ, arbitrary DoT endpoints, client-initiated DNS-over-TCP, direct-IP connections, and general IPv6 traffic are not covered. Only supported UDP DNS packets addressed to PrivaCage's virtual DNS endpoints enter this DNS-only tunnel.
- The encrypted `.pcage` file uses the format documented in `docs/encrypted-profile-format.md`. Anyone who receives both the file and passphrase can read its contents; share the passphrase through a separate trusted channel.
- This code has not been tested on an emulator or physical device. CI and device validation are required before calling it release-ready.
- Catalog parsing is strict and fails visibly in the UI if its schema is invalid; manual rules remain usable. The catalog is bundled at build time, not remotely updated.
- Platform/device policy can prevent VPN or foreground-service startup. Failures stop the service; DNS query names are not logged.
- The lifecycle panel reports PrivaCage's recorded service state, not a DNS leak test. It cannot prove all apps use the virtual DNS endpoint. It does not cover app-initiated DNS-over-TCP, DNS-over-HTTPS, DNS-over-QUIC, arbitrary DoT endpoints, direct-IP connections, or HTTPS payloads.
- DNS route diagnostics are an explicit one-query test of the configured resolver path, not a comprehensive leak test. The response demonstrates only that a matching DNS response came back through that transport at the time tested. Android network capability snapshots can identify a system-detected captive portal or lack of validation but do not prove which route every app uses. Wi-Fi-to-mobile handovers and captive-portal behavior still need emulator/physical-device testing.

- Metadata scrubber limits: recognized JPEG APP1 (EXIF/XMP-class), APP13 (IPTC/Photoshop), and COM segments; PNG EXIF, textual/XMP, timestamp, and physical-resolution chunks; and WebP EXIF/XMP chunks are removed and checked on a separate output. Unsupported metadata types, unrecognized fields/chunks, embedded visual content, and other privacy clues may remain. Inputs over 100 MiB and structurally invalid files are rejected; PNG/JPEG trailing data is rejected, while WebP RIFF sizes, chunk lengths, and padding are checked.

- Roster-owner key rotation uses a dual-signed transition from the current and replacement owner keys, bound to the relay space and exact next roster revision. Import also requires the full replacement fingerprint to be independently confirmed out of band and the next roster to verify. The replacement private bundle stays in the Android Keystore-protected local record; only the signed transition and public roster are exported. The public handoff package is retained in the protected local record for re-copying, and further owner rotation or recovery replacement/export is blocked until the user acknowledges that every intended peer accepted the new owner and roster. That acknowledgement cannot be independently proven by this client. Relay member credentials may need separate administrator replacement, and a lost old owner key cannot perform this continuity-preserving rotation.


## Platform API references checked (3 November 2026)

- Android's [UsageStatsManager API reference](https://developer.android.com/reference/android/app/usage/UsageStatsManager) documents that `queryEvents` requires `PACKAGE_USAGE_STATS` and that usage events are retained by the system for only a few days. PrivaCage requests no app-open observations until the user grants Usage Access in Android Settings and bounds each scan to a recent 24-hour window.
- Android's [package visibility guide](https://developer.android.com/training/package-visibility) describes the manifest `<queries>` declarations used to discover launcher activities without requesting `QUERY_ALL_PACKAGES`. The resulting inventory remains launcher-visible only.
- Android's [`SigningInfo` API reference](https://developer.android.com/reference/android/content/pm/SigningInfo) documents the ordered, oldest-to-current signing history for single-signer packages and the separate multiple-signer model. PrivaCage uses that history only when the independent APK signature verifier accepts the file; otherwise lineage remains unavailable.
