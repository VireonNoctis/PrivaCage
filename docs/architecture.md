# Architecture

## Design goal

Build a local-first privacy auditor with a shared evidence format and platform-native enforcement. Shared code may normalize records and validate data; it must not erase important differences between Android, iOS, and Windows.

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

The Kotlin/JVM core includes a DNS policy evaluator, IPv4 UDP packet codec, packet processor, validated UDP forwarder, protected TCP fallback for truncated upstream responses, and packet-to-packet coordinator. The initial Android app provides a user-configured `VpnService` adapter around that core:

- The user explicitly approves VPN access and enters a numeric IPv4 resolver plus one or more domain rules.
- The service creates a TUN interface with a virtual DNS endpoint and routes only that endpoint into the interface.
- A blocking packet loop sends supported IPv4 UDP DNS queries through the policy engine and writes blocked REFUSED replies or successfully forwarded responses back to the TUN.
- Upstream UDP and TCP sockets are passed to `VpnService.protect` before connecting, preventing resolver traffic from looping back into the VPN.
- A valid UDP response with the DNS TC flag triggers a TCP retry. Response identity, question, resource-record boundaries, compression pointers, and declared lengths are checked before the answer is returned.
- An upstream timeout or transport failure drops that query while keeping the tunnel active; a fabricated DNS answer is never substituted.
- Settings are stored locally. DNS query names are not logged.

This is an early implementation, not release-verified. The app bundles the canonical `shared/tracker-db/signatures.json` at build time and displays each record's status, confidence, verification date, and evidence URLs. The user can explicitly import `active` domain indicators into the local rule editor; they must then save the configuration before those domains become rules. `review` and `retired` entries are not imported by that action, and SDK patterns remain informational because the DNS filter cannot enforce class-level indicators. The current database has only two Analytics endpoint records, so it is not a comprehensive tracker list. The client-facing tunnel accepts IPv4 UDP DNS only; it does not accept DNS-over-TCP connections from apps, handle IPv6 DNS, DoH, DoT, DoQ, app attribution, or HTTPS payload inspection. A full TCP response too large to fit in a UDP response is rejected. Queries are processed sequentially, and no emulator or physical-device test has yet verified routing, lifecycle behavior, or resolver interoperability. These limitations must remain visible until tested and implemented.

The app also presents a local device-privacy snapshot using Android-exposed APIs: location-services state, Wi-Fi radio state, Private DNS mode, and whether the active default network uses a VPN. It also lists PrivaCage's own declared permissions with Android protection-level classifications. It does not read SSIDs, nearby scan results, or location coordinates, and it does not transmit the snapshot. These settings are only indicators: they cannot reveal all system/OEM telemetry or prove that traffic is fully tunneled.

The Android app's bundled catalog must be revalidated in CI whenever the shared tracker database changes. The next Android work should focus on emulator/device validation of VPN authorization, route behavior, packet read/write, revocation, network transitions, resolver failure, and stopping the service. Then implement a downstream TCP DNS endpoint and a deliberate IPv6 strategy before expanding the feature claim. Encrypted DNS protocols and direct-to-IP connections remain outside ordinary DNS filtering.

Do not add permission interception, fake-data injection, or arbitrary sensor monitoring until a supported API or explicitly gated rooted extension actually implements it.

## iOS

Use public Apple APIs and approved entitlements only. NetworkExtension design depends on entitlement approval and distribution route. The companion can explain available privacy reports and native settings but cannot inspect other apps' binaries or override their permissions.

## Windows

Start with read-only inventory of supported firewall state, then add explicit, user-confirmed rules with administrator privileges when needed. Record the exact rule added and verify it after applying. Do not claim unrestricted process attribution from standard firewall APIs alone.

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

This is protocol code only. No relay or account service is implemented; no Android/iOS/Windows keystore adapter or UI is wired to it. The relay will still observe routing metadata, timing, and packet sizes. Group membership, revocation, sequence-order enforcement, conflict resolution, and independent cryptographic review remain required before claiming a complete sync product.


## Opaque encrypted-sync relay

`shared/rust/pcage-sync-relay` is a persistent SQLite-backed HTTP relay. It stores packet bytes as opaque payloads, indexes them by space and message ID, exposes cursor-based reads, expires records after seven days, rejects duplicate IDs, and caps each space at 10,000 queued messages. Space creation, capability rotation, and deletion require a separate admin bearer token; each space capability is stored as a SHA-256 hash. The server never receives a private key or profile plaintext.

The service refuses to bind to a non-loopback address. Remote deployment requires a TLS reverse proxy on the same host forwarding to the loopback listener. The relay still sees space IDs, message IDs, timestamps, packet sizes, and access patterns. Capability tokens are shared by every device in a space, so revoking one device individually requires the future signed roster/revocation layer. The Android/iOS/Windows apps are not yet wired to this service.
