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

Not implemented: network relay, accounts, group roster/revocation, automatic trust-on-first-use, platform keystore adapters, UI flows, iOS/Windows integration, sequence-order enforcement, independent audit, and device/emulator integration tests. Until those are added, this is a protocol core, not a complete sync feature.
