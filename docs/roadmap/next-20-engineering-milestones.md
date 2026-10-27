# Next 20 engineering milestones

**Plan date:** 26 October 2026  
**Execution rule:** each milestone must deliver a working, reviewable change with tests appropriate to the risk. A roadmap item is not a feature claim. Keep implementation in a pull request, verify current-head CI, and do not merge an unverified change.

This sequence follows the existing research roadmap and repository gaps. It prioritizes cross-platform audit consistency and Android network validation before adding new surfaces.

## Milestone sequence

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 1 | Strict Android checkpoint JSON parsing | Reject duplicate JSON keys before Android's `JSONObject` parser can collapse them, including escaped-equivalent keys and duplicates inside the embedded payload. Add regression tests and bound parser nesting. | In PR #10 |
| 2 | Android checkpoint comparison | Let the user select two files through the Storage Access Framework. Verify both before comparing same-signer, same-scope record hashes; show same-chain, prefix, or divergence results without exposing event contents. | Planned |
| 3 | Shared checkpoint edge-case vectors | Add deterministic empty-chain and multi-event fixtures, plus malformed/duplicate-key/tampering cases, consumed by Android, Rust, and Web. Keep test keys non-production. | Planned |
| 4 | Cross-language CI path coverage | Ensure changes to `shared/audit/**` trigger Android, Rust, and Web verifier workflows. Acceptance: a fixture-only change cannot bypass the relevant test suites. | In PR #10 |
| 5 | Android VPN lifecycle integration suite | Add reproducible emulator checks for authorization, start/stop, revocation, service restart and error reporting; distinguish emulator coverage from physical-device/OEM evidence. | Planned |
| 6 | DNS route and network-transition acceptance tests | Exercise the configured virtual IPv4/IPv6 DNS routes, Wi-Fi/mobile handover, resolver failure, and unsupported packet shapes. Confirm unsupported paths fail visibly instead of being reported as protected. | Planned |
| 7 | DNS-over-TLS negative-path validation | Test certificate/hostname failure, unavailable resolver, timeout, and no plaintext fallback where encrypted upstream is selected. Report the observed transport result, not a security guarantee for other apps. | Planned |
| 8 | DNS diagnostic evidence quality | Review each diagnostic field and reason code against actual Android APIs/packet outcomes. Keep unknown attribution visible; do not convert a successful test query into a claim that all app traffic uses the resolver. | Planned |
| 9 | Local DNS-history resilience tests | Cover corrupt ciphertext, missing Keystore key, invalid timestamps, retention boundaries, and storage-write failures. Preserve unreadable evidence and fail closed rather than silently resetting history. | Planned |
| 10 | Audit export redaction test matrix | Test every combination of hostname/socket-owner redaction, filters, invalid records, empty results, and bounded history. Verify raw sensitive values never appear when the report claims they are redacted. | Planned |
| 11 | APK parser hostile-input corpus | Add deterministic malformed and boundary APK fixtures for oversized inputs, ZIP/DEX truncation, malformed manifest data and unexpected compression. Require bounded work and visible failures. | Planned |
| 12 | APK privacy-diff reproducibility | Verify same-input repeatability and explicit unknown states for unsupported signing/DEX constructs; retain APK hashes and catalogue version in reports. Do not add a single “safe” score. | Planned |
| 13 | Tracker evidence freshness gate | Improve the catalogue report with machine-readable stale/missing-evidence output and a CI gate that gives actionable record IDs. Do not auto-promote feed candidates to active blocking rules. | Planned |
| 14 | Reviewed tracker-update workflow | Add a candidate → source review → diff → validation process for catalogue updates, with lifecycle/status checks and documented rollback. No unsourced bulk imports. | Planned |
| 15 | Alternative-app catalogue governance | Test stable IDs, destination allowlist, evidence age and trade-off fields; provide a review report that makes stale entries actionable without auto-downloading or installing apps. | Planned |
| 16 | Metadata scrubber conformance corpus | Add per-format JPEG/PNG/WebP fixtures containing representative metadata and malformed edge cases. Re-parse output and verify declared metadata is gone while the original remains unchanged. | Planned |
| 17 | User-driven metadata share flow | Connect supported metadata cleaning to an explicit share/document workflow only after file-level output verification; clearly label unsupported formats and partial failures. | Planned |
| 18 | Permission-drift baseline migration and diagnostics | Test first scan, incomplete inventory, package disappearance, schema migration, unreadable baseline and reset. Never infer revocation or complete coverage from missing packages. | Planned |
| 19 | Local rights-request assistant v1 | After fresh legal/source review, add locally stored, user-reviewed request drafts, separately configured jurisdiction deadlines, evidence and reminder states. Sending stays explicit; a draft or receipt is not proof of deletion. | Planned |
| 20 | iOS companion capability foundation | Define and test a public-API-only capability matrix and import flows for user-provided reports/files. Build no screen that implies cross-app inspection unless an approved entitlement and working OS path prove it. | Planned |

## Pull-request discipline

- Use a focused PR per milestone or a tightly coupled pair when they share one acceptance criterion.
- Run the checks that cover every changed path and inspect the latest commit's CI rather than relying on an earlier green run.
- Prefer tests that exercise actual parsers, storage, OS results, or cryptographic verification; do not substitute static sample outputs for real behavior.
- Research current platform APIs and legal requirements before milestones 5–8, 11, 16–19, and 20.
- Keep test fixtures synthetic and redacted. Do not commit production keys, real user DNS history, private identifiers, or personal APKs.
- If a milestone requires a capability unavailable to an ordinary app, record the exact blocker and maintain an honest limited behavior instead of adding a fake control.
