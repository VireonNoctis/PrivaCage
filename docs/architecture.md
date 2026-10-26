# Architecture

## Design goal

Build a local-first privacy auditor with a shared evidence format and platform-native enforcement. Shared code may normalize records and validate data; it must not erase important differences between Android, iOS, and Windows.

## Web console

The web workspace is a static Svelte 5 + TypeScript application in `web/`; it is not a JavaScript server or a browser extension. Its separate `web-backend/` Rust/Axum service embeds the canonical `shared/tracker-db/signatures.json` at build time and validates its schema, identifiers, dates, hostnames, status values, and evidence before serving it.

The Rust API exposes:

- `GET /api/health` — reports service health and explicitly says the web workspace has no connected device.
- `GET /api/v1/tracker-catalog` — returns the source-backed catalogue and evidence URLs.
- `GET /api/v1/summary` — derives record/status/category counts from that catalogue.
- `GET /api/v1/capabilities` — identifies which web workspace surfaces are available, platform-local, or not connected.

Catalogue metrics are not device telemetry. The web client does not invent activity events, claim that indicators were observed on a device, or state that any rules were enforced. The Android DNS history remains device-local. The web client does not pair with devices or ingest live events, but it can locally verify and compare signed checkpoint files that the user explicitly selects; those files are processed in the browser and are not uploaded by the verifier.

The Rust API binds to loopback by default. Production deployment should serve the static `web/dist` assets and reverse-proxy same-origin API requests to the Rust service; do not expose the unauthenticated API directly to a public interface. No product analytics or telemetry SDK is included in the web client.

## Proposed layers

1. Platform adapters collect facts exposed by supported OS APIs.
2. An evidence normalizer converts facts into typed events while retaining provenance and confidence.
3. A policy engine evaluates explicit user rules against observable attributes.
4. Enforcement adapters apply rules through supported platform controls and return a result, including failure.
5. A local event store records decisions and evidence with retention controls.
6. The UI explains results without converting guesses into facts.
7. Shared intelligence provides versioned tracker/SDK indicators with evidence URLs and review dates.

If a platform does not expose an event, show that monitoring is unavailable or limited rather than fabricating an event.

## Event model direction

Events should distinguish observed facts, static indicators, inferences, enforcement results, and unknowns. Every event should include a timestamp, platform/source, event type, relevant app identity where the OS supplies it, decision/result where applicable, and evidence provenance. Do not store packet payloads by default.

## Android DNS slice

The Kotlin/JVM core includes a DNS policy evaluator, IPv4 and constrained IPv6 UDP packet codecs, packet processor, validated UDP forwarder, protected TCP fallback for truncated upstream responses, and packet-to-packet coordinator. The Android app provides a user-configured `VpnService` adapter around that core:

- The user explicitly approves VPN access and enters a numeric IPv4 resolver plus one or more domain rules.
- The service creates a TUN interface with a virtual DNS endpoint and routes only that endpoint into the interface.
- A blocking packet loop dispatches supported IPv4 or IPv6 UDP DNS packets through the policy engine, returns REFUSED replies for blocked names, and writes successful upstream responses back to the TUN.
- Upstream UDP and TCP sockets are passed to `VpnService.protect` before connecting, preventing resolver traffic from looping back into the VPN.
- A valid UDP response with the DNS TC flag triggers a TCP retry. Response identity, question, resource-record boundaries, compression pointers, and declared lengths are checked before the answer is returned.
- An upstream timeout or transport failure drops that query while keeping the tunnel active; a fabricated DNS answer is never substituted.
- Settings are stored locally. DNS query names are not logged.

This is an early implementation, not release-verified. The app bundles the canonical `shared/tracker-db/signatures.json` at build time and displays status, confidence, last-reviewed date, and evidence URLs. The tracker catalogue contains 25 source-backed indicator records but is deliberately non-comprehensive. Users can explicitly import only `active` domain indicators into the local rule editor; they must then save the configuration before those domains become rules. `review` and `retired` records are excluded from bulk import, and SDK patterns are informational because DNS cannot enforce class-level indicators. The tunnel now has constrained IPv4 and IPv6 UDP DNS packet handling, routed only to the two virtual DNS endpoints. IPv6 extension headers, fragments and jumbograms are rejected; responses exceeding the configured 1500-byte TUN MTU are dropped rather than truncated. The client-facing tunnel still does not accept DNS-over-TCP connections from apps, inspect HTTPS payloads, attribute each DNS request to an app, or decode DoH/DoQ. DNS-over-TLS can be selected for PrivaCage's upstream transport, but that does not prevent other apps from bypassing the engine with their own encrypted resolver. Upstream TCP fallback is supported for truncated UDP replies. Unit tests are not a substitute for emulator/physical-device validation of routes, lifecycle, resolver interoperability and network transitions.

The app also presents a local device-privacy snapshot using Android-exposed APIs: location-services state, Wi-Fi radio state, Private DNS mode, and whether the active default network uses a VPN. It also lists PrivaCage's own declared permissions with Android protection-level classifications. It does not read SSIDs, nearby scan results, or location coordinates, and it does not transmit the snapshot. These settings are only indicators: they cannot reveal all system/OEM telemetry or prove that traffic is fully tunneled.

The Android app's bundled tracker catalogue must be revalidated in CI whenever the shared tracker database changes. The next Android work should focus on emulator/device validation of VPN authorization, IPv4/IPv6 route behavior, packet read/write, extension-header rejection, revocation, network transitions, resolver failure, and stopping the service. A downstream TCP DNS endpoint remains unimplemented. Encrypted DNS protocols and direct-to-IP connections remain outside ordinary DNS filtering.

Do not add permission interception, fake-data injection, or arbitrary sensor monitoring until a supported API or explicitly gated rooted extension actually implements it.

## Tracker intelligence and installed-app alternatives

The shared tracker catalogue uses schema v1 in `shared/tracker-db/signatures.json`, with stable IDs, typed domain or SDK indicators, explicit confidence and lifecycle status, a human review date, and HTTPS evidence. `active` means eligible for explicit user-reviewed rules; it does not mean globally safe to block or prove runtime collection. SDK class patterns are used by static APK string scanning, not by the DNS engine. The app's Google-suite alternative screen reads `shared/app-alternatives/catalog.json`; it validates exact schema fields and HTTPS destinations against a reviewed-host allowlist, presents known trade-offs/evidence, and stores the user's queue locally. The queue opens one chosen store/project source at a time and relies on that source and Android for download/install. It does not silently download arbitrary APKs or pretend it verifies that installation completed.

## iOS

Use public Apple APIs and approved entitlements only. NetworkExtension design depends on entitlement approval and distribution route. The companion can explain available privacy reports and native settings but cannot inspect other apps' binaries or override their permissions.

## Windows

The Windows Go CLI in `windows/pcage-audit/` now supports a read-only baseline, edition-aware hardening previews, explicit apply, verify, and restore. It queries Domain/Private/Public firewall profiles and selected machine policy values through Windows PowerShell. The balanced profile targets documented diagnostic-data limits, advertising ID, Activity Feed/User Activity sharing, online speech personalization, tailored experiences, and supported Windows 11 diagnostic log/dump limits. The strict profile disables clipboard history and adds selected Windows-app capability force-denials plus Windows Error Reporting policy.

Apply is not implicit: the CLI requires `--confirm`, requests UAC elevation, and refuses to overwrite an active backup. Registry writes are limited to an allowlist and DWORD values. It snapshots prior key/value existence and the old DWORDs before changing policy, restricts the ProgramData backup directory to SYSTEM and Administrators, verifies values after writes, and attempts rollback on failure. Restore restores captured registry values and optional firewall profile state, verifies the result, and removes the backup only after successful readback. A pending backup deliberately prevents applying another profile.

Two network controls are separate from the normal privacy profiles. Default outbound Block changes the default action but does not override all explicit allow rules. Emergency isolation adds a named all-program outbound block rule, enables firewall profiles, and can immediately interrupt all networking, including DNS and Windows Update; it requires a second explicit confirmation and a local recovery path.

The audit and hardening commands make no network requests and do not upload results. A policy registry value is not proof of effective policy or observed network traffic; domain policy and MDM can replace local values. Required diagnostic data remains on common client editions and the Settings selector is locked only on supported builds; administrators or higher-priority management policy can still change it. The Diagnostic data off value is available only on Enterprise, Education, and Server editions per Microsoft's current policy documentation. Windows-app permission policies are not a universal barrier against every desktop program, service, driver, OS component, firmware route, or external network path. This is a reversible policy controller, not a kernel filter or guarantee of zero Windows communications.

## Data flow

OS evidence → typed event → policy evaluation → OS action when supported → verified result → local audit log.

For static scanning: user-selected APK → manifest/DEX inspection → signature matches and evidence → privacy label with uncertainty.

The tracker database is advisory intelligence. It does not replace platform enforcement and is not proof of runtime behavior.

## Encrypted profile export

Android can export the resolver and user-configured domain rules as a versioned `.pcage` file. It derives a 256-bit key from the user passphrase with Argon2id v1.3 (19 MiB memory, 2 iterations, 1 lane), then encrypts and authenticates the payload using AES-256-GCM with a fresh 96-bit nonce. A random 128-bit salt and the nonce are stored in the header; the full header is authenticated as associated data. The full byte-level definition is in `docs/encrypted-profile-format.md`.

The file is encrypted before it is written through Android's Storage Access Framework. Import authenticates/decrypts and validates the complete profile before asking the user to replace local settings. This provides encrypted manual transfer if the passphrase is conveyed separately; it is not account sync, not a server-side messaging system, and not encryption of live DNS queries unless the user separately enables DNS-over-TLS in the VPN configuration. The sender's identity is not authenticated by this passphrase container. Kotlin/JVM and Rust now decrypt a shared known-answer vector, and the Rust crate also validates/serializes the typed profile schema before returning decrypted settings. This proves compatibility for that fixture, not a full audit. Swift/Windows implementations, sender identity, recipient key verification, key rotation, recovery, replay handling, and any network sync protocol remain unimplemented.

## Privacy properties

- No required account or backend for core functionality.
- No outbound analytics or crash-reporting SDK by default.
- Network access by PrivaCage itself must be documented and limited to explicitly requested updates or user-initiated actions.
- Rules and logs remain local unless exported by the user.
- Automatic rule updates require authenticated metadata, integrity checks, and a rollback policy.


## End-to-end encrypted sync protocol core

`shared/rust/pcage-sync` defines device identities using Ed25519 signing keys and X25519 encryption keys. Device cards expose public keys and a SHA-256 fingerprint; the receiving user must verify the fingerprint through a separate trusted channel before trusting the card. Each sync packet uses ephemeral X25519, HKDF-SHA-256, ChaCha20-Poly1305 with an authenticated header, and an Ed25519 signature. The receiver checks sender and recipient binding, signature, expiry, and AEAD authentication, then durably records the message ID before returning plaintext. The crate also creates old-key-signed rotation statements and PCAGE01-encrypted recovery bundles.

The Rust protocol core and Android JNI adapter implement device identity, encrypted packets, durable replay protection, peer-key rotation, dual-signed roster-owner key rotation, recovery bundles, and owner-signed device rosters. Owner-key transitions are bound to the existing space and exact next revision, signed by both the old and new owner keys, and accepted only after independent confirmation of the new full fingerprint plus validation of the replacement roster. Android exposes owner-key rotation export/import controls; private replacement keys remain in the protected local record. Roster updates are manually exported and imported, so revocation and owner transitions do not take effect on another installation until it imports the newer signed state. Relay member credentials may need separate administrator provisioning after rotation. The relay sees routing metadata and can deny service. iOS/Windows key-store adapters, automatic roster distribution, sequence-order enforcement, conflict resolution, and independent cryptographic review remain outstanding.


## Opaque encrypted-sync relay

`shared/rust/pcage-sync-relay` is a persistent SQLite-backed HTTP relay. It stores packet bytes as opaque payloads, indexes them by space and message ID, exposes cursor-based reads, expires records after seven days, rejects duplicate IDs, and caps each space at 10,000 queued messages. Space creation, capability rotation, and deletion require a separate admin bearer token; each space capability is stored as a SHA-256 hash. The server never receives a private key or profile plaintext.

The service refuses to bind to a non-loopback address. Remote deployment requires a TLS reverse proxy on the same host forwarding to the loopback listener. The relay still sees space IDs, message IDs, timestamps, packet sizes, and access patterns. Capability tokens are shared by every device in a space, so revoking one device individually requires the future signed roster/revocation layer. The Android/iOS/Windows apps are not yet wired to this service.


## Multi-format metadata inspection and scrubbing

The Android file-picker flow stages only the user-selected image in the app cache and calls `shared/rust/pcage-metadata` through `shared/rust/pcage-metadata-jni`. It supports JPEG, PNG, and WebP with a 100 MiB input cap. Inspection does not modify the selected file. Scrubbing writes a separate temporary copy, validates the output with a second parser pass, and offers it to the user only when no metadata recognized by the parser remains. The input file is never overwritten and no image bytes are uploaded.

The core preserves JPEG APP markers other than APP1, APP13, and COM; preserves unknown PNG/WebP extension chunks and ICC color profiles to avoid destroying potentially important rendering information; and reports those limitations explicitly. PNG chunk CRCs, WebP RIFF/chunk lengths and padding, JPEG marker boundaries, truncation, and trailing data are checked. The core does not decode pixels, prove every image decoder will render the result, or remove identifying information embedded in the visible image content. This is a format-bounded metadata scrubber, not a universal anonymizer.


## Windows customization handoff

The Windows workspace exposes two intentionally separate control surfaces:

- `windows/pcage-audit/` is PrivaCage's own Go implementation. Its changes stay within a documented registry/firewall allowlist, use explicit confirmation, save a rollback snapshot, and verify the requested values.
- `windows/Win11Debloat/` is a pinned, MIT-licensed upstream Win11Debloat component. It supplies the broader Windows customization GUI/CLI, app removal, UI/registry tweaks, optional-feature changes, import/export, localization, and upstream restore/backup tooling.

The `pcage-audit debloat` command only launches the upstream entry point. It does not apply defaults, claim that all settings are reversible, or pretend that PrivaCage's policy backup can restore actions outside its own allowlist. The upstream tool may request UAC and mutate Windows after the user selects operations. Review its current documentation and choices before applying changes. CI checks out the pinned submodule and parses the PowerShell source, but parsing is not a runtime safety proof; the upstream Pester suite remains the source project's behavior test suite.
