# PrivaCage PCAGE crypto core (Rust)

This crate implements the portable .pcage v1 envelope specified in docs/encrypted-profile-format.md. It is a small cross-platform cryptographic boundary, not a network service or account-sync backend.

## API

- encrypt(plaintext, passphrase) creates a fresh envelope using an OS-backed CSPRNG for the salt and nonce.
- decrypt(envelope, passphrase) validates size and magic before deriving a key and authenticates the complete header before returning plaintext.
- profile::ProfilePayload validates the strict versioned profile JSON schema, numeric IPv4 resolver, normalized domain labels, and duplicate rules; typed encrypt/decrypt helpers never return a profile until authentication and schema validation both succeed.
- KDF parameters and maximum input sizes are constants, never parsed from untrusted file bytes.
- Derived keys and temporary salt/nonce arrays are zeroized with zeroize wrappers.

## Test

From the repository root:

    cargo fmt --manifest-path shared/rust/pcage-crypto/Cargo.toml --all -- --check
    cargo test --manifest-path shared/rust/pcage-crypto/Cargo.toml
    cargo clippy --manifest-path shared/rust/pcage-crypto/Cargo.toml --all-targets -- -D warnings

The tests decrypt the same checked-in known-answer envelope as the Kotlin/JVM core. The fixed salt and nonce belong only to that test vector. Production encryption obtains fresh random values and does not expose a deterministic-encryption API.

## Security scope

This crate implements encrypted file envelopes only. It does not provide sender identity, accounts, key exchange, sync, network transport, or encryption for live DNS. A passphrase holder can decrypt the file. A wrong passphrase, modified authenticated header, or modified ciphertext is rejected.

The profile helpers zeroize their temporary plaintext buffers on drop. The passphrase is borrowed from the caller and cannot be zeroized by this crate. The derived key is zeroized on drop. Zeroization is best-effort process-memory hygiene, not protection against a compromised OS or every possible compiler/hardware side channel.
