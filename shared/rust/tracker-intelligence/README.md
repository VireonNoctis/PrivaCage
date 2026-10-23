# PrivaCage Tracker Intelligence (Rust)

## Build and tests
```sh
cargo test
cargo run -- validate ../../tracker-db/signatures.json
cargo run -- migrate-v1 ../../tracker-db/signatures.json /tmp/intelligence-v2.json
cargo run -- validate-v2 /tmp/intelligence-v2.json
cargo run -- validate-sources ../../tracker-db/source-registry.json
cargo run -- freshness ../../tracker-db/signatures.json "$(date -u +%F)" 180 /tmp/tracker-freshness.json
cargo run -- analyze ../../tracker-db/signatures.json www.google-analytics.com
cargo run -- analyze-v2 /tmp/intelligence-v2.json domain www.google-analytics.com
cargo run -- analyze-v2 /tmp/intelligence-v2.json ip_address 192.0.2.1
cargo run -- ingest ../../tracker-db/signatures.json /tmp/observations.json /tmp/candidates.json /tmp/ingest-manifest.json ./observations.json ./domains.txt
cargo run -- scan-apk ../../tracker-db/signatures.json app.apk /tmp/apk-observations.json /tmp/apk-report.json
cargo run -- diff old-v2.json new-v2.json /tmp/catalog-diff.json
cargo run -- graph /tmp/intelligence-v2.json /tmp/intelligence-graph.json
cargo run -- regressions old-v2.json new-v2.json /tmp/regressions.json
cargo run -- history ./release-store "$PCAGE_TRUSTED_PUBLIC_KEY_HEX"
cargo run -- review-candidate /tmp/candidates.json domain collector.example.net accept reviewer-id "confirmed by primary documentation" 2026-10-23 ./review-ledger.jsonl
```

## Release workflow
Set a 32-byte Ed25519 seed in a secret manager or protected environment variable; never commit it or put it in shell history.

```sh
cargo run -- publish catalog.json ./release-store release-2026-10-23 2026-10-23 "$PCAGE_ED25519_SEED_HEX"
cargo run -- verify-current ./release-store "$PCAGE_TRUSTED_PUBLIC_KEY_HEX"
cargo run -- rollback ./release-store release-2026-10-01 "$PCAGE_TRUSTED_PUBLIC_KEY_HEX"
```

Candidate reviews append JSONL decisions with a previous-record hash chain. The chain detects edits to individual records, but it is not a digital signature and does not authenticate the self-declared reviewer; protect and externally back up the ledger for stronger audit guarantees.

The release store keeps immutable `releases/<id>/catalog.json` and `manifest.json`, plus an atomically replaced `current.json` pointer. Rollback verifies the selected release against a separately pinned trusted public key before changing the pointer. Back up the release directory; this is a local release store, not a remote distribution/rollback service.

## Implemented behavior and limits
- Legacy schema-v1 catalog load/validation remains supported.
- V1-to-v2 migration preserves entries and aggregates evidence into the bundle source list; it does not invent company/SDK relationships.
- Schema-v2 validation checks identifiers, evidence, domains, hashes, and entity/SDK references.
- Local ingestion accepts typed JSON observations or newline-separated domains; it normalizes/deduplicates and creates candidates without auto-publishing them.
- Static APK scanning reads DEX files from ZIP/APK archives, extracts printable ASCII strings, compares them with catalog DEX indicators, and records the APK SHA-256. It does not extract package IDs from binary AndroidManifest.xml, certificate identity from APK signing blocks, runtime behavior, or network destinations.
- Catalog diff produces added, removed, and changed entries.
- Ed25519 release signing/verification and local immutable release snapshots/rollback are implemented. Pin the public key out-of-band.
- Exact DNS-label-boundary matching prevents substring matches. Indicator association is not proof of SDK execution, sensitive-data access, exfiltration, or malicious intent.

## Not implemented here
Live VPN/DNS telemetry still requires platform-specific Android VPN-service integration and OS-permitted iOS networking APIs. Automatic internet feed crawling and publication require source-specific adapters, licensing/provenance rules, network/privacy policy, and maintainer review; this crate deliberately accepts local feed exports instead of inventing a universal scraper. A dashboard and multi-user review service require the app/backend's actual UI and API surfaces.
