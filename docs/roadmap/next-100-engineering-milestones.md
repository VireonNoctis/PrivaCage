# Next 100 engineering milestones

**Sequence:** milestones 21–120, continuing after `next-20-engineering-milestones.md`  
**Execution mode for this run:** direct commits to `main`, as explicitly requested; no PR is being created.  
**Rule:** a listed milestone is not a completion claim. Status changes only after implementation evidence and relevant CI checks. Platform integration, legal sign-off and hardware-dependent items stay blocked until that evidence exists.

## Working order

The first focus is integrity of persisted state and hostile-input handling. Next come DNS enforcement evidence, APK and metadata parser resilience, tracker provenance, encrypted sync, Windows rollback correctness, and web/backend privacy boundaries. Features that cannot be validated in this repository (physical device routing, Xcode signing/entitlements, legally reviewed templates) remain explicit external acceptance gates.

## Milestone register

| # | Milestone | Deliverable and acceptance criteria | Initial / current status |
|---:|---|---|---|
| 21 | Strict JSON parsing across persisted local state | Apply the duplicate-key scanner to persisted profile, tracker, history, rights-request and sync records; reject malformed/unknown fields before state mutation. | Core sources wired; latest Android CI needs confirmation |
| 22 | Permission baseline corruption recovery | Preserve unreadable baseline bytes until explicit reset; distinguish missing, valid, invalid and oversized baseline states in report copy. | Implemented; CI pending |
| 23 | Deterministic DNS parser mutation corpus | Seeded mutations of DNS headers, QNAME, EDNS records and packet lengths must never throw, hang, or forward malformed input. | Implemented; fix assertion signatures and rerun |
| 24 | DNS transport no-plaintext fallback matrix | Test TLS handshake failure, hostname mismatch, timeout, socket protection failure and malformed replies; encrypted-upstream selection must never downgrade silently. | Unit coverage partial; live TLS test remains |
| 25 | DNS replay and query/response correlation | Verify transaction ID, question name/type/class and endpoint matching in transport response validation with deterministic malformed reply fixtures. | Partially covered; expand UDP and DoT cases |
| 26 | DNS timeout and cancellation semantics | Prove sockets close on timeout/interruption and caller cancellation cannot leave blocked worker threads or late responses. | Planned |
| 27 | IPv4 fragmentation boundary matrix | Cover reserved flags, DF, MF, fragment offsets, header options, checksum and total-length boundaries with explicit Drop/NotDns outcomes. | Core tests exist; broader corpus planned |
| 28 | IPv6 extension-header rejection matrix | Test every supported/unsupported extension header, jumbograms, truncated options and fragments; no malformed packet is sent upstream. | Core limitation implemented; corpus planned |
| 29 | DNS route diagnostics provenance | Represent the diagnostic as a timestamped probe with selected network, resolver result and limitations; never imply all traffic is covered. | Partially covered; device API evidence needed |
| 30 | VPN lifecycle instrumentation boundaries | Test permission denied, start/stop, repeated start, revoked consent and stale process state; device-route claims only from emulator/device integration. | State tests exist; full lifecycle needs emulator |
| 31 | TUN read/write failure behavior | Test EOF, partial write, descriptor closure, IOException and service stop; status must become stopped/error rather than remain active. | Planned |
| 32 | Network handover acceptance | Instrument Wi-Fi/cellular transitions on emulator with expected routes and resolver reachability; record exact emulator image/API. | Device-dependent |
| 33 | VPN conflict detection | Show likely conflict when another VPN is active using documented APIs and explicit uncertainty; do not claim to name every competing provider. | Planned; public-API research required |
| 34 | DNS block-rule import review | Preview count, normalized domains, duplicates, invalid rules and source provenance before an explicit import transaction. | Core normalization exists; UI acceptance planned |
| 35 | DNS rule-set rollback | Snapshot prior rules and atomically restore on parse/write failure; tests prove failed import does not leave partial state. | Planned |
| 36 | DNS cache and policy versioning | If caching is added, bind entries to normalized question, policy version and resolver scope; invalidate blocked/stale decisions correctly. | Not implemented; require measured need first |
| 37 | DNS performance regression stability | Separate noisy emulator startup failures from benchmark regressions; persist complete benchmark environment and repeated-run statistics. | Existing benchmark workflow sometimes fails emulator bootstrap |
| 38 | DNS privacy-safe event taxonomy | Ensure events distinguish blocked/forwarded/dropped/diagnostic and include rule IDs without raw payload retention. | Partial; schema and UI audit planned |
| 39 | DNS log retention UI conformance | Test every retention option, pruning at exact cutoff, invalid timestamps and storage failure without erasing source on parse failure. | Core pure tests exist; UI/device tests pending |
| 40 | DNS encrypted-history key-loss handling | On Keystore invalidation, preserve ciphertext, report recovery choices and never silently create a new key over unreadable history. | Cipher tests exist; device Keystore invalidation test pending |
| 41 | APK ZIP structural limits | Test entry count, duplicate names, compressed-size inflation, malformed central directory and unsupported compression under a bounded CPU/memory budget. | Entry ceiling test started; expand corpus |
| 42 | DEX parser scope contract | Document that embedded strings are scanned heuristically, not full bytecode validated; distinguish malformed DEX from no indicators and unsupported formats. | Scanner disclaimer exists; status taxonomy planned |
| 43 | APK signature verification negative corpus | Cover unsigned APKs, unknown signature schemes, malformed certificates, multiple signers and platform verification limits. | Existing verifier; corpus expansion planned |
| 44 | APK signing-certificate continuity | Compare signer certificates across versions; distinguish expected rotation from mismatch and state when lineage cannot be validated. | Fingerprint utility exists; lineage-aware behavior planned |
| 45 | APK export-component risk context | Include exported component kind, permission gate, intent filters and parser uncertainty without translating declaration into exploitability. | Current component diff; report context planned |
| 46 | APK privacy diff stable sorting | Guarantee stable output across ZIP entry order, catalog input order and repeated run; include scanner/catalog hashes. | Repeatability tests started; full permutation test planned |
| 47 | Tracker association confidence calibration | Define evidence-based confidence tiers and test shared-CDN, first-party analytics and static-string false positives. | Current confidence labels exist; calibration needs researched data |
| 48 | APK report provenance bundle | Record APK SHA-256, signer fingerprints, version, Android tool/scanner version and catalog hash in the exported report. | Core report partly includes provenance; end-to-end report planned |
| 49 | APK parser fuzz harness | Run bounded seeded/randomized ZIP/DEX/manifest inputs in CI and fail on crashes, hangs or unbounded resource growth. | Seeded corpus planned |
| 50 | APK report safe-language review | Remove binary safe/unsafe scores; label observed declarations, static matches, unknowns, and evidence limits consistently. | Already follows policy in core; UI copy audit pending |
| 51 | Metadata scrubber multi-format conformance suite | Maintain canonical JPEG, PNG and WebP fixtures with metadata before/after, file-boundary corruption and output re-parse assertions. | Rust coverage exists; expand fixture inventory |
| 52 | Metadata output atomicity | Write to a temporary sibling file, verify output, then atomically replace the destination where supported; preserve original on failure. | Rust core has temp output; cross-platform tests needed |
| 53 | Metadata cleanup idempotence | Scrubbing an already-clean fixture twice must produce equivalent bytes and zero claimed removals on second pass. | Partly tested; conformance extension planned |
| 54 | Metadata preserve-visual-data contract | Verify retained image payload/scan data and critical color chunks; document that metadata removal does not detect sensitive pixels. | Core has sample payload checks; more fixture coverage planned |
| 55 | Malformed WebP RIFF corpus | Test chunk-size overflow, padding, EXIF/XMP feature flags, unknown chunk preservation and truncation. | Rust partial coverage |
| 56 | Malformed PNG chunk corpus | Test CRC, critical/ancillary chunk ordering, IEND, trailing bytes and length overflow; reject invalid output without touching input. | Rust partial coverage |
| 57 | JPEG scan-marker corpus | Cover progressive scans, stuffed bytes, restart markers, fill bytes, truncated segment lengths and invalid marker order. | Core coverage exists; more edge vectors planned |
| 58 | Metadata privacy preview | Before sharing, show format, output size, metadata categories removed, unsupported categories retained and verification result. | Share flow exists; detailed preview planned |
| 59 | Share-sheet URI permission lifecycle | Grant read-only URI access to the cleaned copy, test cancellation and provider failure, and delete temporary files at documented lifecycle boundaries. | Current share flow exists; device lifecycle test pending |
| 60 | Metadata scrub audit receipt | Generate a local non-sensitive receipt with input/output hashes, format, parser version, removal counts and verification outcome. | Planned |
| 61 | Tracker catalog source registry integrity | Validate every record's source-registry ID and URL against allowlisted evidence; reject orphan references and duplicate source identities. | Current schema validates URLs; cross-registry checks planned |
| 62 | Tracker catalog per-entry review dates | Version schema to record evidence review date separately from catalog update date; add migration and stale/evidence-unknown states. | Blocked on schema-v2 design |
| 63 | Tracker catalog update provenance | Record reviewed commit, source URLs, reviewer decision and normalized diff for each catalog update. | Candidate issue form exists; automation planned |
| 64 | Tracker lifecycle state machine | Define active/review/retired transitions and require current evidence for reactivation; CI rejects illegal lifecycle jumps. | Existing statuses; transition policy planned |
| 65 | Tracker false-positive fixture suite | Maintain positive and negative examples for each indicator type, including shared infrastructure and lookalike domain boundaries. | Partial; curated corpus planned |
| 66 | Tracker evidence retrieval policy | Do not fetch evidence URLs inside the app; offline review tooling may validate HTTPS/reachability with rate limits and clear source date. | Manual review policy exists; controlled tooling planned |
| 67 | Tracker signed-release manifest | Publish a signed manifest binding catalog hash, schema version, update time and toolchain; reject rollback/replay in update tooling. | Rust crypto primitives exist; release binding planned |
| 68 | Tracker catalog reproducible packaging | Verify same inputs produce identical normalized catalog output and hash; exclude timestamps that break reproducibility. | Planned |
| 69 | Tracker ID and domain tombstones | Avoid accidentally reusing retired tracker IDs or reintroducing invalidated indicators; maintain reason and provenance for removals. | Planned |
| 70 | Tracker data quality dashboard | Show counts by status/confidence, evidence age and missing fields with no unsupported total-tracker claims. | Catalog validator exists; dashboard planned |
| 71 | Alternative-app per-entry freshness schema | Introduce per-entry checked_at and source IDs in a versioned schema; migration must keep old entries explicitly unknown. | Catalogue-level freshness only |
| 72 | Alternative-app replacement suitability filters | Filter by platform, license, offline support, account requirement, telemetry disclosure and material trade-offs. | Current catalog has partial tradeoff fields; schema expansion planned |
| 73 | Alternative-app destination validation | Revalidate HTTPS, approved host, package identifier and redirect policy in offline validator without auto-installing anything. | Host validation exists; package links validation planned |
| 74 | Rights assistant deadline engine test matrix | Cover calendar-month rollover, leap day, end-of-month, extensions and jurisdiction-specific response rules with official source references. | Core date helpers exist; legal review required |
| 75 | Rights tracker state transition validation | Reject impossible status transitions, record only user-reported timestamps and preserve distinction between sent, acknowledged and outcome. | Status tracking exists; deeper transition tests planned |
| 76 | Rights tracker storage minimization | Reject duplicate keys/unknown fields, bound serialized bytes and record count, and guarantee delete clears only local tracker metadata. | Core strict JSON and size limit added; CI pending |
| 77 | Rights request draft safety copy | Separate draft generation, copying, opening official guidance and user-confirmed submission; never infer submission from opening a URL. | Current UI copy exists; UI test planned |
| 78 | Rights source drift monitor | CI snapshots official reference links and review dates; notify maintainers for dead links or changed text, never present snapshots as current law without review. | Planned; networked scheduled CI required |
| 79 | DROP manual workflow acceptance | Test user-guided browser handoff, official identity steps, and accurate broker update timing; no automated submission or scraping. | Manual guide exists; flow tests planned |
| 80 | Legal-template release sign-off | Require qualified privacy-law review before calling templates jurisdiction-specific legal guidance. | Release blocker |
| 81 | Encrypted backup envelope corpus | Add truncation at every boundary, oversized lengths, altered salt/nonce/header/tag and malformed passphrase Unicode tests. | Core crypto tests exist; boundary corpus planned |
| 82 | Encrypted backup cross-language vectors | Publish non-production interoperable vectors generated and verified independently by Rust/JVM implementations. | One interoperability vector exists; more boundary vectors planned |
| 83 | Passphrase memory hygiene audit | Track byte/char buffer ownership across backup/sync calls and clear mutable material on every success/failure path. | Core clears some buffers; call-site audit planned |
| 84 | Sync peer-card duplicate-key validation | Strict-parse peer cards and local persisted sync records before trusting keys or changing roster state. | Current sync uses JSONObject; strict validation integration planned |
| 85 | Sync profile schema strictness | Reject unknown, duplicate, missing and wrongly typed fields before a received profile is staged for user review. | Current validation exists; duplicate-key scan planned |
| 86 | Sync anti-replay lifecycle tests | Cover replay ledger corruption, clock skew, expired messages, duplicate packet IDs and crash between ledger/cursor writes. | Rust replay protection exists; Android lifecycle tests needed |
| 87 | Sync cursor atomicity | Atomically persist replay ledger, receive cursor and pending profile state; crash tests prove no accepted message is skipped or applied twice. | Planned |
| 88 | Sync key rotation recovery | Fault-inject before/after signing, storing and publishing staged rotations; require recoverable explicit state at every step. | Existing staged rotation; fault-injection matrix planned |
| 89 | Sync revoked-peer quarantine | Verify a revoked sender cannot leave approvable pending payloads or wedge relay cursors; test signed roster lag explicitly. | Core behavior exists; regression tests planned |
| 90 | Sync relay privacy review | Document exactly what relay sees (routing metadata, timing, sizes) and what encrypted content it cannot decrypt; revalidate transport and logging. | Existing architecture; source-level audit planned |
| 91 | Web checkpoint verifier hostile corpus | Share all vectors with Rust/Android, including duplicate escaped keys, invalid base64, malformed ECDSA, deep JSON and oversized payloads. | Shared vectors exist; full parity matrix planned |
| 92 | Web checkpoint comparison UX accessibility | Keyboard navigation, accessible relationship labels, copy/export, and explicit mismatch reasons; no event content shown by default. | Comparison UI exists; accessibility suite planned |
| 93 | Web API outbound-request inventory | Test every frontend fetch destination and ensure audit checkpoints/files never upload by accidental API calls. | API tests exist; outbound inventory planned |
| 94 | Dashboard local-data boundary tests | Prove imported audit files remain in memory and are not written to local storage, analytics or server requests. | Web verifier local-only; automated network assertions planned |
| 95 | Backend request-size and schema limits | Bound body sizes, request rates and JSON fields at every endpoint; test oversized, duplicate and deeply nested input. | Current API controls need complete inventory |
| 96 | Backend retention/deletion acceptance | For every persistent store, specify retention, deletion semantics, backups and logs; test delete propagation and non-retention where promised. | Data inventory needed |
| 97 | CSP and web security header audit | Deploy and test Content-Security-Policy, Referrer-Policy, nosniff, permissions policy and TLS assumptions for dashboard/backend. | Planned; verify real deployment before claim |
| 98 | Dependency vulnerability and license inventory | Generate repeatable SBOMs for Gradle, Cargo, Go and npm; surface advisories and license conflicts without silently updating dependencies. | Planned |
| 99 | Release artifact provenance | Record source commit, toolchain versions, dependency lockfile hashes, test results and signed artifact hashes. | Planned |
| 100 | Reproducible Android build investigation | Compare independent release builds and document non-reproducible sources; do not claim reproducibility until byte-level verification succeeds. | Planned |
| 101 | Windows audit read-only safety suite | Mock PowerShell/registry responses and assert audit-only commands do not mutate host policy. | Current unit tests partial; integration suite planned |
| 102 | Windows firewall policy rollback | Test snapshots, partial mutation failures, restoration failures and post-restore re-read; show exact policies not restored. | Existing reversible actions; fault tests planned |
| 103 | Windows registry policy type safety | Cover absent values, wrong registry types, denied access and conflicting policy sources with explicit unknown/error states. | Current collector handles some types; tests planned |
| 104 | Windows DNS/proxy provenance | Distinguish user proxy, system DNS, per-interface DNS and VPN state; avoid claiming browser traffic uses a given path. | Current collector partial; report improvement planned |
| 105 | Windows restore-point and recovery gate | Require explicit consent and capability checks for high-impact reversible hardening; never call an operation reversible without verification. | Planned |
| 106 | Windows command execution policy | Pin executable paths where feasible, use argument arrays, bound output/time, and classify exit code/stderr without shell concatenation. | Collector uses subprocess; comprehensive tests planned |
| 107 | Windows report redaction matrix | Prevent user names, paths, network IDs, proxy URLs and tokens from entering reports by default; search outputs for seeded secrets. | Planned |
| 108 | Windows platform CI truthfulness | Run Windows-specific PowerShell/registry tests on Windows runner and keep non-Windows skips visible; do not equate cross-compile with runtime validation. | Workflow exists; inspect job semantics |
| 109 | Cross-platform fixture parity | Use same JSON, malformed input and cryptographic vector corpus in Kotlin, Rust, Go and TypeScript where semantics overlap. | Some shared vectors exist; broaden parity |
| 110 | Privacy regression seeded-secret scanner | Inject synthetic secrets into fixtures and scan build artifacts/logs/reports for leakage in CI. | Planned |
| 111 | Local-only guarantee test inventory | Instrument network calls around features labeled local-only and fail tests if those code paths transmit user content. | Planned |
| 112 | Permission/request rationale UX audit | For every sensitive Android permission, document purpose, denial behavior, and why settings handoff is used instead of bypass. | Planned |
| 113 | Backup/restore retention review | Verify exclusions in Android backup/data extraction and ensure exported encrypted backups are never auto-uploaded. | Manifest exists; full restore/device validation pending |
| 114 | Crash/report telemetry check | Inventory crash analytics, logging endpoints and debug prints; assert private DNS/history and sync payloads are not logged. | Planned |
| 115 | Threading and cancellation test suite | Exercise lifecycle cancellation and I/O failures across DNS, file import, local history and sync without leaked workers. | Planned |
| 116 | Storage failure injection | Test full disk, read-only provider, failed atomic commit, permission loss and interrupted import with original-state preservation. | Planned |
| 117 | Accessibility for privacy warnings | Ensure redaction, attribution uncertainty and irreversible-action warnings are announced and readable with larger text and screen readers. | Planned |
| 118 | Security disclosure and incident workflow | Add a private reporting route, response commitments, triage severity model and credential/key-compromise guidance. | Planned |
| 119 | Platform capability matrix update | For each OS release, link to official API docs and explicitly mark supported, unsupported, gated and untested behaviors. | Planned; update per OS release |
| 120 | Release gate and limitations report | Generate a release checklist from CI, open blockers, platform matrix, legal review and privacy test evidence; block release on missing required sign-offs. | Planned |

## Status and merge policy

- Direct commits are being made to `main` for this requested run. Keep commits scoped, avoid unrelated refactors, and inspect the exact head SHA when evaluating CI.
- `Implemented` means code and appropriate tests exist. `Verified` additionally requires relevant checks to pass on the same head.
- `Device-dependent`, `legal review required`, and `requires an iOS project/entitlement` are real blockers, not tasks that should be bypassed with placeholders.
- Network-visible features must document what the external service can observe. Local-only features need request-inventory tests rather than relying only on UI copy.
- A tracker match, permission declaration, network destination, rights-request draft, or signed audit checkpoint is evidence with a defined scope; none alone proves maliciousness, data misuse, identity, trusted time, completeness of monitoring, or successful deletion.
- Synthetic fixtures only. Never commit production keys, private user history, actual personal identifiers, or unlicensed APKs.
