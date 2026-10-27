# pcage-audit

Portable offline verifier for PrivaCage schema-v1 signed audit checkpoints.

## Use

From the repository root:

    cargo run --manifest-path shared/rust/pcage-audit/Cargo.toml -- path/to/checkpoint.json

Exit status is 0 only when the checkpoint signature, embedded payload digest, schema, redaction claims, counters, and every event-chain link validate. Invalid, oversized, ambiguous, unsupported, or inconsistent input returns a non-zero exit code. The CLI reads at most 2 MiB before parsing and does not make network requests.

The verifier accepts only the repository's current v1 format: P-256 SubjectPublicKeyInfo public keys, SHA256withECDSA signatures, at most 100 records, a 1 MiB embedded payload, and strict JSON fields. The shared fixtures cover a zero-event genesis chain, one event, and a two-event chain, and are also consumed by Android and Web tests. A schema change must be versioned and accompanied by updated cross-implementation vectors.

## Trust boundary

A successful verification establishes that the exact embedded payload matches the signed digest and that the embedded P-256 key verifies the signature and chain. It does not establish who controls the key, whether the device clock is correct, whether all events were recorded, or whether events were omitted before the snapshot was signed. Independently compare the reported SHA-256 public-key fingerprint with a trusted channel. The tool is read-only and never writes to the checkpoint.
