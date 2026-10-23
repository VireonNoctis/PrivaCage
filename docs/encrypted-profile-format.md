# Encrypted profile format v1

This document specifies the portable `.pcage` binary envelope used for Android profile export/import. It is intended to be implementable by future Rust, Swift, and Windows clients without changing the format.

## Security scope

The envelope encrypts the profile fields currently exported by Android: the numeric IPv4 resolver and the configured blocked-domain list. It is encrypted on the exporting device before the document is handed to the storage provider. A receiver needs the file and the passphrase. The passphrase must be conveyed separately using a channel the user trusts.

This is encrypted file transfer, not a synced account, not encryption of live DNS traffic, and not sender identity/authentication. There is no cloud key escrow or recovery route. Losing the passphrase means the profile cannot be recovered. A party with both file and passphrase can decrypt it. The file size and its fixed magic/version remain visible.

## Binary layout

All offsets are zero-based. Integers are not needed in the v1 header; all fields have fixed lengths.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 8 bytes | Magic/version: ASCII `PCAGE01` followed by one zero byte |
| 8 | 16 bytes | Fresh cryptographically random salt |
| 24 | 12 bytes | Fresh cryptographically random AES-GCM nonce |
| 36 | variable | AES-GCM ciphertext followed by the 16-byte authentication tag |

The authenticated additional data (AAD) is bytes 0 through 35 inclusive. No KDF cost or algorithm parameters are read from the file; v1 parameters are fixed so a malicious file cannot request excessive KDF work.

## Cryptographic parameters

- Passphrase encoding: UTF-8 bytes of the exact passphrase text; no Unicode normalization is performed. Interoperable implementations must use the same Unicode code-point sequence.
- Key derivation: Argon2id v1.3 (Argon2 version 19), 19,456 KiB memory, 2 iterations, parallelism 1, 16-byte random salt, 32-byte output key.
- Encryption: AES-256-GCM, 12-byte nonce, 128-bit authentication tag.
- Randomness: OS cryptographic random generator for the salt and nonce; both are independently sampled on each export.
- Resource limits: plaintext at most 1,048,576 bytes; envelope at most 1,048,628 bytes. Android only imports profile payloads whose JSON schema and domain rules validate.

The Android implementation uses Bouncy Castle 1.86 for Argon2id and the platform JCA provider for AES-GCM. The binary version and algorithm parameters must not be silently changed. A future incompatible format must use a new magic/version and separately reviewed tests.

## Profile plaintext schema

The plaintext is UTF-8 JSON with exactly these fields:

```json
{
  "format_version": 1,
  "resolver_ipv4": "192.0.2.53",
  "blocked_domains": ["ads.example", "tracker.example"]
}
```

The IP in this example is documentation-only, not a recommended DNS resolver. Production import rejects unknown/missing fields, non-numeric IPv4 resolver addresses, empty rule lists, duplicate/non-normalized domains, and invalid hostnames. The example values are illustrative only.

## Implementation requirements for other platforms

1. Validate the 8-byte magic and envelope length before performing key derivation.
2. Use the fixed v1 Argon2id parameters above; do not take cost parameters from untrusted input.
3. Treat bytes 0–35 as AES-GCM AAD.
4. Do not expose partially decrypted data. A failed authentication tag must result in complete rejection.
5. Validate the complete JSON profile before displaying or applying any imported settings.
6. Do not log passphrases, derived keys, plaintext profile bytes, or DNS query names.
7. Clear temporary password/key/plaintext buffers on a best-effort basis.
8. Do not claim a file authenticates who created it. V1 proves only that the contents authenticate under the key derived from the supplied passphrase.
