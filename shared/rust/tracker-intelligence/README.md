# PrivaCage Tracker Intelligence (Rust)

Offline-capable intelligence core that reads the existing schema-v1 file at `shared/tracker-db/signatures.json`, preserving current Android catalog compatibility.

## Commands

Run in this directory:

```sh
cargo test
cargo run -- validate ../../tracker-db/signatures.json
cargo run -- analyze ../../tracker-db/signatures.json www.google-analytics.com
cargo run -- discover ../../tracker-db/signatures.json observations.json
cargo run -- build-release catalog.json release-manifest.json 2026-10-23 "$PCAGE_ED25519_SEED_HEX"
cargo run -- verify-release catalog.json release-manifest.json "$PCAGE_TRUSTED_PUBLIC_KEY_HEX"
```

Observation files are JSON arrays with `value`, `kind` (`domain`, `package_id`, `certificate_sha256`, `dex_string`, or `file_hash_sha256`), and optional `context`.

## Guarantees and limits

- Domain matching is case-insensitive and supports exact hostnames or DNS-label-boundary subdomains; it never uses substring matching.
- Review entries stay review-only. Unknown observations become review candidates, not automatic catalog entries or maliciousness claims.
- Identity association, evidence quality, and detection coverage are separate scores. Static indicators do not establish runtime execution, payload contents, exfiltration, or malicious intent.
- Release manifests sign the SHA-256 digest of exact catalog bytes with Ed25519. Verification requires a separately pinned trusted public key; never trust the key solely because an untrusted manifest supplies it.
- Keep private signing seeds out of source control, logs, and shell history. Prefer a secret manager or protected environment variable.
- Catalog structure validation does not prove evidence accuracy or source independence.

The engine implements catalog loading/validation, domain/package/certificate/hash/string matching, candidate discovery, explicit entity/SDK graph correlation, confidence dimensions, and signed release verification. It does not itself scrape external feeds, inspect live traffic, extract DEX strings from APKs, auto-publish candidates, or operate a remote rollback service. Those need separate ingestion policy, source-specific adapters, platform integrations, and operational trust configuration.
