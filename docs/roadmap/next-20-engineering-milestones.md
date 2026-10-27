# Next 20 engineering milestones

**Plan date:** 26 October 2026  
**Execution rule:** each milestone must deliver a working, reviewable change with tests appropriate to the risk. A roadmap item is not a feature claim. Keep implementation in a pull request, verify current-head CI, and do not merge an unverified change.

This sequence follows the existing research roadmap and repository gaps. It prioritizes cross-platform audit consistency and Android network validation before adding new surfaces.

## Milestone sequence

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 1 | Strict Android checkpoint JSON parsing | Reject duplicate JSON keys before Android's `JSONObject` parser can collapse them, including escaped-equivalent keys and duplicates inside the embedded payload. Add regression tests and bound parser nesting. | Merged in PR #10 |
| 2 | Android checkpoint comparison | Let the user select two files through the Storage Access Framework. Verify both before comparing same-signer, same-scope record hashes; show same-chain, prefix, or divergence results without exposing event contents. | Implemented in batch; CI pending |
| 3 | Shared checkpoint edge-case vectors | Add deterministic empty-chain, one-event and two-event signed fixtures consumed by Android, Rust and Web; preserve malformed/duplicate-key/tampering cases. Test keys are not checked in. | Implemented in batch; CI pending |
| 4 | Cross-language CI path coverage | Ensure changes to `shared/audit/**` trigger Android, Rust, and Web verifier workflows. Acceptance: a fixture-only change cannot bypass the relevant test suites. | Merged in PR #10 |
| 5 | Android VPN lifecycle integration suite | Core VPN state/unit tests exist. End-to-end authorization, revocation, process restart and OEM lifecycle validation still require a dedicated emulator/physical-device suite; unit tests do not claim route coverage. | Additional integration suite required |
| 6 | DNS route and network-transition acceptance tests | Core packet tests cover constrained IPv4/IPv6 paths and unsupported packets. Wi-Fi/mobile handover, actual TUN routes and device-level resolver behavior still need emulator/physical-device validation. | Partially covered; device validation pending |
| 7 | DNS-over-TLS negative-path validation | Added tests for socket-protection failure and an injected TLS handshake/certificate-validation failure; verify no DNS query is sent in plaintext. Real resolver certificate/hostname validation still needs an integration test against a configured test server. | Partially implemented in batch; CI pending |
| 8 | DNS diagnostic evidence quality | Existing diagnostics tests distinguish a resolved answer, NXDOMAIN, missing answer, mismatched transaction ID/question, and timeout; output remains resolver-probe evidence, not proof that every app uses that resolver. | Existing unit coverage; device-route proof pending |
| 9 | Local DNS-history resilience tests | Existing tests cover corrupt stored JSON, retention boundaries, invalid timestamps, AES-GCM tampering, incorrect keys, and bounds. Keystore key-loss/storage-failure lifecycle still needs a device-level test. | Existing unit coverage; device lifecycle pending |
| 10 | Audit export redaction test matrix | Added all four hostname/socket-owner redaction combinations, fixed-redaction assertions, empty-filtered export/genesis head, and byte-deterministic export tests. | Implemented in batch; CI pending |
| 11 | APK parser hostile-input corpus | Existing malformed-ZIP/no-DEX cases are supplemented with a 10,000-entry archive-limit test. This scanner is a bounded DEX-string scanner, not a full DEX verifier; native code/DEX structural validity is not claimed. | Partially implemented; CI pending |
| 12 | APK privacy-diff reproducibility | Added repeatability tests for identical scanner inputs/catalogues and identical APK privacy diffs; existing reports preserve APK/catalogue hashes and avoid a single safety score. | Implemented in batch; CI pending |
| 13 | Tracker evidence freshness gate | Existing Go/Rust tracker validation and CI freshness checks report stale catalogue evidence. A catalogue match remains advisory and does not activate rules automatically. | Existing workflow; regression test in CI |
| 14 | Reviewed tracker-update workflow | Added a GitHub issue form requiring exact evidence URL, review date, indicator values, confidence, false positives, limitation statements and acknowledgement that proposals are not auto-activated. Promotion remains a maintainer review step. | Candidate intake implemented; review remains manual |
| 15 | Alternative-app catalogue governance | Existing Android/Go tests cover schema, unique IDs, HTTPS destinations/approved hosts and trade-off fields. Added a machine-readable report and CI gate for catalogue `updated_at` freshness, with each record ID in the report. Individual source-review dates remain unavailable in schema v1 and are explicitly reported as unknown. | Implemented catalogue-level freshness gate; per-entry review dates require schema change |
| 16 | Metadata scrubber conformance corpus | Existing Rust metadata-core tests cover JPEG, PNG and WebP chunk/segment handling, malformed bounds and output validation. Android uses the Rust native scrubber and returns per-format removal counts; real share-output review remains necessary. | Existing core tests; CI revalidation pending |
| 17 | User-driven metadata share flow | Added an explicit share-sheet action for the latest saved, verified cleaned image in the current app session. It sends only that cleaned URI, never the selected original; unsupported formats remain outside the supported JPEG/PNG/WebP list. | Implemented in batch; CI pending |
| 18 | Permission-drift baseline migration and diagnostics | Existing permission snapshot tests cover requested/granted changes and disappearing packages without false revocation claims. Incomplete-inventory and persisted-baseline schema-migration tests remain outstanding. | Existing diff coverage; migration tests pending |
| 19 | Local rights-request assistant v1 | Added Android-local UK GDPR/California CCPA draft generation, a user-guided DROP checklist, a bounded metadata-only tracker, explicit user-reported statuses, receipt-date planning, delete controls and official source links. It never sends requests or stores draft/contact/document contents. Qualified legal review is a release blocker. | Implemented in batch; legal review required |
| 20 | iOS companion capability foundation | Added `ios/README.md` with allowed public-API work, forbidden claims, required acceptance tests and exact environment/entitlement blockers. No executable iOS target is present and no runtime feature is claimed. | Design boundary documented; iOS project/entitlement required |

## Pull-request discipline

- Use a focused PR per milestone or a tightly coupled pair when they share one acceptance criterion.
- Run the checks that cover every changed path and inspect the latest commit's CI rather than relying on an earlier green run.
- Prefer tests that exercise actual parsers, storage, OS results, or cryptographic verification; do not substitute static sample outputs for real behavior.
- Research current platform APIs and legal requirements before milestones 5–8, 11, 16–19, and 20.
- Keep test fixtures synthetic and redacted. Do not commit production keys, real user DNS history, private identifiers, or personal APKs.
- If a milestone requires a capability unavailable to an ordinary app, record the exact blocker and maintain an honest limited behavior instead of adding a fake control.
