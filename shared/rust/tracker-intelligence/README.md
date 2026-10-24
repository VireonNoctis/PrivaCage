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
cargo run -- analyze-v2 /tmp/intelligence-v2.json sdk_pattern "Lcom/example/sdk/Tracker;"
cargo run -- ingest ../../tracker-db/signatures.json /tmp/observations.json /tmp/candidates.json /tmp/ingest-manifest.json ./observations.json ./domains.txt
cargo run -- scan-apk ../../tracker-db/signatures.json app.apk /tmp/apk-observations.json /tmp/apk-report.json
cargo run -- diff old-v2.json new-v2.json /tmp/catalog-diff.json
cargo run -- graph /tmp/intelligence-v2.json /tmp/intelligence-graph.json
cargo run -- dashboard /tmp/intelligence-v2.json /tmp/intelligence-dashboard.html
cargo run -- serve-dashboard /tmp/intelligence-v2.json 127.0.0.1:8787
cargo run -- fetch-feed ../../tracker-db/signatures.json ../../tracker-db/source-registry.json feed-stevenblack-personal-hosts 2026-10-24 /tmp/feed-observations.json /tmp/feed-candidates.json /tmp/feed-manifest.json
cargo run -- regressions old-v2.json new-v2.json /tmp/regressions.json
cargo run -- history ./release-store "$PCAGE_TRUSTED_PUBLIC_KEY_HEX"
cargo run -- review-candidate-signed /tmp/candidates.json domain collector.example.net accept reviewer-id "confirmed by primary documentation" 2026-10-24 ./signed-review-ledger.jsonl "$PCAGE_REVIEWER_SEED_HEX" ./reviewer-keys.json\ncargo run -- verify-review-ledger ./signed-review-ledger.jsonl ./reviewer-keys.json
```

## Release workflow
Set a 32-byte Ed25519 seed in a secret manager or protected environment variable; never commit it or put it in shell history.

```sh
cargo run -- publish catalog.json ./release-store release-2026-10-23 2026-10-23 "$PCAGE_ED25519_SEED_HEX"
cargo run -- verify-current ./release-store "$PCAGE_TRUSTED_PUBLIC_KEY_HEX"
cargo run -- rollback ./release-store release-2026-10-01 "$PCAGE_TRUSTED_PUBLIC_KEY_HEX"
```

The legacy `review-candidate` command writes hash-chained but unsigned records. For authenticated review, `review-candidate-signed` requires a 32-byte Ed25519 seed whose public key matches the reviewer ID in a trusted `reviewer-keys.json` registry; `verify-review-ledger` verifies every signature, reviewer mapping, record hash, and chain link. Never commit signing seeds. Strict verification rejects unsigned legacy records; keep legacy and signed ledgers separate or migrate them through an explicitly reviewed process.

The release store keeps immutable `releases/<id>/catalog.json` and `manifest.json`, plus an atomically replaced `current.json` pointer. Rollback verifies the selected release against a separately pinned trusted public key before changing the pointer. Back up the release directory; this is a local release store, not a remote distribution/rollback service.

## Implemented behavior and limits
- Legacy schema-v1 catalog load/validation remains supported.
- V1-to-v2 migration preserves entries and aggregates evidence into the bundle source list; it does not invent company/SDK relationships.
- Schema-v2 validation checks identifiers, evidence, domains, hashes, and entity/SDK references.
- Local ingestion accepts typed JSON observations or newline-separated domains; it normalizes/deduplicates and creates candidates without auto-publishing them.
- `fetch-feed` is an explicit, user-triggered HTTPS adapter for the registered MIT-licensed StevenBlack personal hosts source. It enforces a 32 MiB cap, rejects redirects and unexpected content types, records feed/catalog hashes, and writes only unreviewed candidates. It is not scheduled, and a hosts-list domain is not automatically classified as a tracker.
- `serve-dashboard` is a loopback-only local dashboard server. It reloads the bundle on each request, refreshes the page every 30 seconds, and rejects non-loopback bind addresses; it is not a remote multi-user service.
- Static APK scanning reads DEX files from ZIP/APK archives, extracts printable ASCII strings, compares them with catalog DEX indicators, parses the package ID and declared permissions from binary AndroidManifest.xml, and extracts SHA-256 fingerprints from supported v2/v3 APK signing blocks. Signing-block extraction is not cryptographic signature verification; v1-only and ZIP64 signer extraction remain unsupported. These are static declarations/identities, not runtime behavior or network destinations.
- Catalog diff produces added, removed, and changed entries.
- `dashboard` generates a self-contained offline HTML report for a validated schema-v2 bundle, with catalog counts, indicator values, evidence links, and escaped record text. `serve-dashboard` serves the report locally and refreshes it against the current bundle.
- Ed25519 release signing/verification and local immutable release snapshots/rollback are implemented. Pin the public key out-of-band.
- Exact DNS-label-boundary matching prevents substring matches. Indicator association is not proof of SDK execution, sensitive-data access, exfiltration, or malicious intent.

## Not implemented here
Live VPN/DNS telemetry still requires platform-specific Android VPN-service integration and OS-permitted iOS networking APIs. Scheduled multi-source crawling and publication remain intentionally disabled. Only one manually triggered, license-reviewed host-file adapter is enabled; additional formats need source-specific parser, license, and provenance review. The local dashboard is loopback-only and has no multi-user authentication or remote review API.
