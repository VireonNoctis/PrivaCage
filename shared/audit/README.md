# Shared audit checkpoint fixtures

## Canonical schema-v1 vector

`test-vectors/checkpoint-v1.json` is the single checked-in signed checkpoint fixture for cross-implementation verification. Keep its embedded `payload_json` string byte-for-byte unchanged when updating the outer JSON: the payload digest covers the exact UTF-8 bytes of that string.

The current fixture is consumed by:

- `shared/rust/pcage-audit/src/lib.rs` — Rust portable verifier tests.
- `web/src/lib/audit-checkpoint.test.ts` — browser Web Crypto verifier tests.
- `android-app/app/src/test/kotlin/org/privacage/android/LocalAuditCheckpointSignerTest.kt` — Android checkpoint verifier tests.

All three implementations must accept the same fixture and detect the same payload mutation: replacing `[REDACTED]` with `private.example` without updating the signed digest.

## Security boundary

This file is test data, not a production identity credential. Its embedded public-key fingerprint is useful for deterministic interoperability tests only. A valid signature from an embedded key does not establish a person's identity, a trusted time, or completeness of the original device history.

Do not put production private keys, personal DNS records, or real user identifiers in shared fixtures.
