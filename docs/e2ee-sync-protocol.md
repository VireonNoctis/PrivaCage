# PrivaCage E2EE sync protocol v1

## Scope

This document describes the Rust client-side protocol in `shared/rust/pcage-sync`. It is not a production service specification. Existing PCAGE01 profile exports remain unchanged.

## Device identity and trust

Each device has an Ed25519 signing key and an X25519 encryption key. Its identity card publishes both public keys, a monotonically increasing key epoch, a device ID derived from the SHA-256 digest of the concatenated public keys, and the full digest as a fingerprint. A card is untrusted until its fingerprint is independently verified, for example by comparing it in person or through a separate trusted channel. HTTPS alone does not prove a relay's card belongs to the intended device.

## Message format

A message includes protocol version, random message ID, sender and recipient IDs/fingerprints, sender sequence, creation and expiry times, ephemeral X25519 public key, random 96-bit nonce, ciphertext, and Ed25519 signature. The header is authenticated as AEAD associated data. Encryption uses ephemeral-static X25519, HKDF-SHA-256 with the message ID as salt and both device IDs in the info string, and ChaCha20-Poly1305. The signed packet body covers the header and all encryption fields. The payload limit is 1 MiB and message lifetime is capped at seven days.

The relay can see routing metadata, packet sizes, timing, device IDs, and message IDs. It cannot decrypt payloads without the recipient's private key. Metadata privacy is not provided. In per-device relay mode, each request carries an Ed25519 proof-of-possession signature over the method, exact path and query, timestamp, nonce, and raw-body digest. The relay verifies it against the public card enrolled for that fingerprint, rejects timestamps more than 120 seconds from server time, and durably rejects reused nonces. Legacy shared-capability spaces remain bearer-only until the administrator explicitly activates per-device mode.

## Replay and key lifecycle

The receiver verifies sender identity, recipient, signature, lifetime, and AEAD tag before recording the message ID in a durable replay ledger. The ledger is single-writer and bounded to 100,000 IDs; applications must serialize access and implement a safe archive/rotation policy before it fills. A crash after the ledger is persisted but before the application consumes plaintext can cause the message to be dropped on retry, which is safer than accepting replay. Sequence numbers are authenticated but the current core does not enforce monotonic per-sender sequence ordering.

A key rotation statement is signed by the previous device key and names the next identity card and epoch. Peers must verify it using the already trusted old card before changing trust state. This proves continuity from the old key, not that the old device was not compromised. Android supports local peer revocation: a removed fingerprint is kept in an encrypted denylist, its pending profile is discarded, and messages from it are skipped. Re-trust requires independently confirming and re-entering the full fingerprint. This only revokes trust on that Android installation; it cannot erase data already copied to the peer or revoke that peer from other installations. The relay supports admin-provisioned per-device credentials keyed by full fingerprints, token-free member listings, selective revocation/replacement, and a one-way switch that disables the legacy shared capability. In member mode, a request must prove possession of the enrolled Ed25519 signing key as well as present its bearer credential. Membership enrollment is still controlled by the relay administrator, not by an owner-signed roster, and compromise of both the token and identity private bundle defeats this binding.

Recovery bundles contain the identity seeds and card, encrypted with the existing PCAGE01 passphrase envelope. Import restores the same long-term identity keys and card rather than generating a new physical-device identity. Two installations using the same recovery bundle therefore share that cryptographic identity; recovery import does not revoke the original installation. For suspected device loss or compromise, revoke the member credential through the relay administrator and locally revoke the fingerprint on other trusted installations. If the space has not migrated to member mode, rotating the shared relay capability still affects every device using it. Recovery data must be stored offline and separately from its passphrase; the relay must never receive it.

## Implementation boundaries

Implemented in this milestone: Rust identity generation, identity-card validation/fingerprints, encrypted and signed per-recipient packets, packet expiry, durable replay protection, signed key rotation, encrypted recovery bundle, and automated unit tests.

Android now has a Rust-JNI client integration: the app wraps its passphrase-encrypted identity bundle and relay capability in an AES-GCM record encrypted with an Android Keystore key, validates public identity cards, requires user-confirmed out-of-band fingerprint comparison before trusting peers, sends signed/encrypted settings profiles through the HTTPS-only relay, stages received profiles in protected local storage until user approval, and supports local peer revocation with a persistent fingerprint denylist.


## Relay boundary test

The relay crate's automated test suite exercises a real encrypted packet created by one `pcage-sync` identity through the authenticated relay HTTP handlers and recovers the recipient identity from its passphrase-encrypted recovery bundle before decrypting. The test verifies unauthenticated-read rejection, successful recipient-side decryption, wrong-recovery-passphrase rejection, and replay rejection using the durable ledger. It runs in-process and is not a substitute for deployed TLS or physical-device testing.


## Android client integration and limits

The Android app loads the shared Rust protocol through `shared/rust/pcage-sync-jni`. Its local record is encrypted with AES-GCM under Android Keystore and includes the locally encrypted identity bundle, relay capability, trusted public cards, inbox cursor, and pending profile. The inner identity bundle uses the existing PCAGE01 Argon2id/AES-256-GCM envelope. A separate recovery export requires a user-chosen passphrase and should be stored offline; it must never be uploaded to the relay.

The user must compare the complete SHA-256 fingerprint through a separate trusted channel before trusting a peer. Relay transport requires HTTPS and rejects redirects to avoid forwarding bearer capabilities to another origin. The app sends only its DNS settings profile, not logs or the whole app configuration. Received payloads are signature-checked, recipient-bound, decrypted through the shared Rust crate, schema-validated locally, staged in the encrypted record, and applied only after explicit confirmation. Revoking a peer removes local trust and any pending profile, then causes packets bearing that revoked fingerprint to be skipped. Restoring a recovery bundle preserves the same identity; it is not equivalent to rotating device keys. The relay supports per-device bearer credentials keyed by full SHA-256 fingerprints. An operator can provision token hashes and validated public cards, explicitly activate one-way per-device authorization, inspect a token-free roster, and rotate or revoke one credential. After activation, the legacy shared capability is rejected. Member-mode requests prove possession of the enrolled Ed25519 signing key by signing the exact HTTP method, path/query, timestamp, nonce, and body digest. Enrollment remains controlled by the relay administrator rather than an owner-signed roster. Clients still validate packet identity and signatures, and the operator must protect the server admin token and distribute device credentials out of band. The relay still sees routing identifiers, timing, packet sizes, and access patterns. Hardware-backed Keystore behavior depends on the device; CI and in-process relay tests do not replace physical-device validation.
