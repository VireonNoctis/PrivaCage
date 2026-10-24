# PrivaCage E2EE sync protocol v1

## Scope

This document describes the Rust client-side protocol in `shared/rust/pcage-sync`. It is not a production service specification. Existing PCAGE01 profile exports remain unchanged.

## Device identity and trust

Each device has an Ed25519 signing key and an X25519 encryption key. Its identity card publishes both public keys, a monotonically increasing key epoch, a device ID derived from the SHA-256 digest of the concatenated public keys, and the full digest as a fingerprint. A card is untrusted until its fingerprint is independently verified, for example by comparing it in person or through a separate trusted channel. HTTPS alone does not prove a relay's card belongs to the intended device.

## Message format

A message includes protocol version, random message ID, sender and recipient IDs/fingerprints, sender sequence, creation and expiry times, ephemeral X25519 public key, random 96-bit nonce, ciphertext, and Ed25519 signature. The header is authenticated as AEAD associated data. Encryption uses ephemeral-static X25519, HKDF-SHA-256 with the message ID as salt and both device IDs in the info string, and ChaCha20-Poly1305. The signed packet body covers the header and all encryption fields. The payload limit is 1 MiB and message lifetime is capped at seven days.

The relay can see routing metadata, packet sizes, timing, device IDs, and message IDs. It cannot decrypt payloads without the recipient's private key. Metadata privacy is not provided.

## Replay and key lifecycle

The receiver verifies sender identity, recipient, signature, lifetime, and AEAD tag before recording the message ID in a durable replay ledger. The ledger is single-writer and bounded to 100,000 IDs; applications must serialize access and implement a safe archive/rotation policy before it fills. A crash after the ledger is persisted but before the application consumes plaintext can cause the message to be dropped on retry, which is safer than accepting replay. Sequence numbers are authenticated but the current core does not enforce monotonic per-sender sequence ordering.

A key rotation statement is signed by the previous device key and names the next identity card and epoch. Peers must verify it using the already trusted old card before changing trust state. This proves continuity from the old key, not that the old device was not compromised. Revocation, group membership, and recovery approval still require an application-level signed roster protocol.

Recovery bundles contain the identity seeds and card, encrypted with the existing PCAGE01 passphrase envelope. The app must show a clear warning to store recovery data offline and separately. The relay must never receive recovery bundles.

## Implementation boundaries

Implemented in this milestone: Rust identity generation, identity-card validation/fingerprints, encrypted and signed per-recipient packets, packet expiry, durable replay protection, signed key rotation, encrypted recovery bundle, and automated unit tests.

Android now has an initial Rust-JNI client integration: the app wraps its passphrase-encrypted identity bundle and relay capability in an AES-GCM record encrypted with an Android Keystore key, validates public identity cards, requires user-confirmed out-of-band fingerprint comparison before trusting peers, sends signed/encrypted settings profiles through the HTTPS-only relay, and stages received profiles in protected local storage until the user approves applying them. This is not complete account/device sync. Not implemented: iOS/Windows clients, an account service, signed group roster/revocation, conflict resolution, sequence-order enforcement, independent cryptographic audit, TLS deployment validation, or representative physical-device lifecycle testing.


## Relay boundary test

The relay crate's automated test suite exercises an encrypted packet created by `pcage-sync` through the relay HTTP handlers: capability-authenticated upload, unauthenticated-read rejection, cursor retrieval, and successful recipient-side signature/decryption/replay-ledger validation. The test runs in-process and is not a substitute for a deployed TLS endpoint or mobile-device integration. Platform-protected key storage, trusted-device enrollment, revocation, conflict handling, and app UI remain unimplemented.


## Android client integration and limits

The Android app loads the shared Rust protocol through `shared/rust/pcage-sync-jni`. Its local record is encrypted with AES-GCM under Android Keystore and includes the locally encrypted identity bundle, relay capability, trusted public cards, inbox cursor, and pending profile. The inner identity bundle uses the existing PCAGE01 Argon2id/AES-256-GCM envelope. A separate recovery export requires a user-chosen passphrase and should be stored offline; it must never be uploaded to the relay.

The user must compare the complete SHA-256 fingerprint through a separate trusted channel before trusting a peer. Relay transport requires HTTPS and rejects redirects to avoid forwarding bearer capabilities to another origin. The app sends only its DNS settings profile, not logs or the whole app configuration. Received payloads are signature-checked, recipient-bound, decrypted through the shared Rust crate, schema-validated locally, staged in the encrypted record, and applied only after explicit confirmation. The relay still sees routing identifiers, timing, packet sizes, and access patterns. Hardware-backed Keystore behavior depends on the device; CI and in-process relay tests do not replace physical-device validation.
