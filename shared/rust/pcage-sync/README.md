# PrivaCage end-to-end sync protocol core

This crate is the client-side cryptographic protocol foundation for multi-device sync. It is not a complete account service or production-ready sync product.

## Implemented

- Ed25519 signing identity plus X25519 encryption identity per device.
- Public identity cards with SHA-256 fingerprints. A card from an untrusted relay is not trusted until the fingerprint is compared through an independent channel.
- Per-recipient encrypted messages using ephemeral X25519, HKDF-SHA-256, and ChaCha20-Poly1305. The message header is authenticated as AEAD associated data, and the packet body is Ed25519-signed.
- Sender and recipient binding, sequence number, bounded lifetime, signature verification, and expiry checks.
- A durable replay ledger written atomically before decrypted plaintext is returned. It is single-writer; callers must serialize concurrent access to the same ledger path.
- Signed identity-key rotation statements that must be verified against the previously verified card.
- Passphrase-encrypted identity recovery bundles using the existing PCAGE01 envelope. Recovery is only as strong as the recovery passphrase and storage location.

## Required integration work

- Android/iOS/Windows adapters must store private seeds in their platform-protected key stores; do not write raw identity seeds to ordinary preferences or logs.
- The first device's fingerprint must be verified out of band when adding another device. Never auto-trust a card supplied by a relay.
- The application must verify rotation statements and explicitly update its trusted-device roster.
- Losing or revoking a device is not solved by rotating one device's key. A signed group roster and revocation protocol are still required.
- A synchronized network relay is not included in this crate. The relay should store opaque signed ciphertext only, authenticate space capabilities, enforce size/retention limits, and never receive private keys or plaintext.
- No iOS or Windows platform key-store adapter is implemented here, and no independent cryptographic audit has been performed.

## Validation

`cargo test --manifest-path shared/rust/pcage-sync/Cargo.toml`
`cargo clippy --manifest-path shared/rust/pcage-sync/Cargo.toml --all-targets -- -D warnings`

Do not use this protocol to claim full end-to-end synchronization until the platform integrations, trusted-device roster/revocation, relay, and multi-device lifecycle tests exist.
