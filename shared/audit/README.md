# Shared audit checkpoint fixtures

## Canonical schema-v1 vector

`test-vectors/checkpoint-v1.json` is the canonical one-event fixture. `checkpoint-v1-empty.json` covers the zero-event genesis chain, and `checkpoint-v1-multi-event.json` covers ordered multi-event chaining. All are signed test vectors for cross-implementation verification. Keep its embedded `payload_json` string byte-for-byte unchanged when updating the outer JSON: the payload digest covers the exact UTF-8 bytes of that string.

The current fixture is consumed by:

- `shared/rust/pcage-audit/src/lib.rs` — Rust portable verifier tests.
- `web/src/lib/audit-checkpoint.test.ts` — browser Web Crypto verifier tests.
- `android-app/app/src/test/kotlin/org/privacage/android/LocalAuditCheckpointSignerTest.kt` — Android checkpoint verifier tests.

All three implementations consume the same three acceptance vectors and detect the same payload mutation: replacing `[REDACTED]` with `private.example` without updating the signed digest. These vectors use test-only keys generated for fixtures; their private keys are not checked in.

## Security boundary

This file is test data, not a production identity credential. Its embedded public-key fingerprint is useful for deterministic interoperability tests only. A valid signature from an embedded key does not establish a person's identity, a trusted time, or completeness of the original device history.

Do not put production private keys, personal DNS records, or real user identifiers in shared fixtures.
