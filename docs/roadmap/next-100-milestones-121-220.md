# Next 100 engineering milestones (121–220)

**Execution mode:** direct commits to `main`; no pull request requested.  
**Scope:** a forward plan after milestones 21–120, plus work is only considered complete when code and relevant tests exist. `Planned` does not mean implemented.  
**Working rule:** repair regressions before stacking more changes. Device, Apple entitlement, production deployment and qualified legal-review dependencies remain explicit gates.

## How to use this register

- Keep each milestone reviewable and preserve working behavior unrelated to its acceptance criteria.
- Require a concrete test, reproducible command or external acceptance artifact for status changes.
- Never use placeholder/mock data as evidence; distinguish a static signal from runtime behavior and an inference from an observation.
- Link every status change to a commit or CI run. External prerequisites are not to be simulated.


## Encrypted sync and device trust

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 121 | Strict JSON on every sync mutation boundary | Reject duplicate keys and unsupported fields before updating peer cards, rosters, owner-rotation packages, replay state, or profile state; test every parser entry point. | Inbound relay packets are byte-bounded and strict-parsed before JSONObject; cards/profiles, signed rosters and protected sync records are strict-parsed; unknown protected-record fields now fail closed; CI pending |
| 122 | Sync record schema version inventory | Enumerate persisted record versions and explicitly migrate or reject unknown versions without discarding records. | Protected envelope and record versions now require an exact integer, not optInt coercion; unit tests added; broader optional-field inventory pending |
| 123 | Atomic sync identity writes | Simulate failed temp writes, interrupted commits, malformed existing records, and KeyStore mismatch; previous record remains intact on failure. | Planned |
| 124 | Trusted-peer roster consistency | Property-test sorted members, duplicate fingerprints, revoked tombstones, and owner-only signing through rotations. | Planned |
| 125 | Replay ledger crash recovery | Test crashes between packet authentication, replay-ledger update, cursor update, and user approval; replay never becomes accepted. | Planned |
| 126 | Relay cursor transaction semantics | Ensure rejected, untrusted, and malformed items advance only under documented policy and never skip a valid item silently. | Planned |
| 127 | Owner rotation interruption matrix | Test each rotation/handoff restart point, old/new signer correspondence, rollback, and retry without losing the transition package. | Planned |
| 128 | Recovery import anti-overwrite gate | Test malformed and oversized recovery bundles, active pending rotations, and failed KeyStore replacement; existing identity survives failure. | Planned |
| 129 | Peer-card hostile input corpus | Fuzz lengths, key encodings, fingerprint casing, URL-like fields, unknown fields, and Unicode without auto-trusting any card. | Planned |
| 130 | Sync privacy telemetry audit | Search logs, exception text, crash paths, and relay errors for passphrases, profile bodies, capability tokens, and raw encrypted packets. | Planned |

## Local storage integrity and recovery

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 131 | Strict JSON Unicode edge cases | Test unpaired surrogates, escaped controls, surrogate-pair escapes, malformed Unicode sequences, and canonical duplicate-key equivalence. | Android scanner rejects unpaired escaped/literal surrogates; tracker asset decoding rejects malformed UTF-8; Go reader rejects invalid UTF-8 and unpaired surrogate escapes. Regression tests added; CI pending |
| 132 | Strict JSON depth boundary | Verify exact accepted and rejected nesting limits in Android, Rust, Web, and Go with shared vectors. | Android scanner and Go tracker reader enforce bounded nesting; tests added; cross-language parity still pending |
| 133 | Strict JSON input budget audit | Inventory every scanner call and enforce byte limits before scanning; reject oversized input before allocating parse trees. | Go tracker reader now has an 8 MiB read ceiling before JSON parsing; Android entrypoint limits are partial, audit remains open |
| 134 | Baseline migration contract | Document schema migration policy and test v1, future version, missing fields, unknown fields, duplicate keys, and explicit reset. | v1 exact keys/types and oversized/count boundaries are tested; wrong-type SharedPreferences values now produce a preserved/unreadable state instead of crashing; broader migration matrix pending |
| 135 | Storage corruption recovery UI | Every unreadable store offers preserve/export/reset options; never auto-reset private history or keys after parse failure. | Planned |
| 136 | Keystore invalidation UX | Simulate invalidated, missing, unavailable, and permanently unusable keys; preserve encrypted evidence and provide truthful recovery choices. | Device-dependent |
| 137 | Atomic preference state updates | Test write failure and process interruption for permission baselines, history preferences, and rights tracker; no partially updated JSON. | Planned |
| 138 | Secure temp-file cleanup | Verify failed imports and scrub jobs remove temporary outputs, while saved source files and prior successful outputs remain untouched. | Planned |
| 139 | Retention configuration schema | Validate persisted retention values and migration paths; expose effective duration and unknown/error states without changing user data silently. | Planned |
| 140 | Local privacy-data inventory | List every preference, database, file, cache, clipboard handoff and temporary directory with owner, sensitivity, retention, and delete path. | Planned |

## DNS policy and protocol correctness

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 141 | DNS escaped-name and compression policy | Test escaped label bytes, invalid label octets, compression pointers, pointer loops and pointer cycles; reject ambiguous names deterministically. | Planned |
| 142 | DNS QNAME mutation corpus | Share reproducible malformed QNAME vectors across Kotlin and Rust consumers where applicable; no parser exceptions or forwarding on malformed input. | Partially covered; expand corpus |
| 143 | EDNS OPT record boundaries | Test multiple OPT records, malformed option lengths, oversized UDP payload advertisements, and unknown option handling. | Planned |
| 144 | DNS response question equality | Test question name, type, class, transaction ID, resolver endpoint and truncation flag for UDP and DoT replies. | Existing checks; broaden matrix |
| 145 | DNS resolver retry policy | Specify retry count, backoff, duplicate query semantics and overall deadline; unit tests prove bounded retries and no hidden downgrade. | Planned |
| 146 | DNS TCP fallback behavior | If truncation requires TCP, implement only with explicit limits and protected sockets; otherwise document and test refusal rather than ambiguous success. | Research and product decision required |
| 147 | DNS EDNS privacy behavior | Document whether ECS/other client-subnet options are forwarded; add deliberate stripping or preservation tests based on an explicit policy. | Planned |
| 148 | DNS negative caching safety | If caching is introduced, bind negative cache to resolver and TTL, cap memory, version policy, and test policy changes invalidate entries. | Not implemented; avoid until measured need |
| 149 | DNS rule normalization parity | Use identical normalization vectors for ASCII case, final dots, IDNA/punycode, wildcards and invalid labels across all ingest paths. | Planned |
| 150 | DNS block reason determinism | Give every Drop/Blocked/NotDns outcome a stable reason code and test localized UI never changes the machine-readable cause. | Planned |

## VPN lifecycle and transport evidence

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 151 | TUN short-read and EOF matrix | Inject zero-length, partial, EOF and exception reads; service status must not report active after loop termination. | Planned |
| 152 | TUN short-write and closure matrix | Inject partial writes, closed descriptors and failures; no busy loop, silent packet loss claim, or stale ACTIVE status. | Planned |
| 153 | VPN stop cancellation semantics | Verify stop interrupts blocked reads and closes protected sockets; worker threads terminate within a bounded deadline. | Device integration pending |
| 154 | Repeated VPN start-stop stress | Run many controlled start/stop cycles in emulator tests and inspect leaked threads, descriptors and stale notifications. | Device integration pending |
| 155 | VPN consent revocation handling | Revoke OS VPN consent and verify service stops and reports it without attempting to bypass the system dialog. | Device-dependent |
| 156 | Network handover telemetry | Record network identity transitions only through documented APIs; report resolver-probe results per network with explicit coverage scope. | Device-dependent |
| 157 | Competing VPN detection UX | Use only available system signals, label guesses, and test that absence of a conflict signal is not stated as proof no other VPN exists. | Planned |
| 158 | DNS resolver configuration drift | Snapshot effective protected resolver target and configuration source, then test invalid/missing/stale configuration states. | Planned |
| 159 | Clock jump diagnostics | Test wall-clock rollback, forward jump and monotonic duration handling so latency/ordering displays do not trust wall time blindly. | Planned |
| 160 | VPN health checklist | Generate a local diagnostic report of service state, route assumptions, resolver probe and last error without hostnames or packet payloads by default. | Planned |

## APK and app analysis

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 161 | ZIP duplicate-entry handling | Create APK fixtures with duplicate normalized names and prove the scanner chooses a documented deterministic policy rather than ambiguous first/last wins. | Planned |
| 162 | ZIP bomb expansion budget | Bound compressed and uncompressed entry sizes and total bytes read; malicious ratios stop with an explicit finding. | Planned |
| 163 | ZIP central-directory consistency | Reject truncated, overlapping, inconsistent and out-of-range central-directory records without unbounded allocation. | Planned |
| 164 | DEX string scan scope labels | Report scanned DEX count, skipped items and parser limits separately; never conflate no matches with full DEX verification. | Planned |
| 165 | DEX method and descriptor false-positive suite | Add benign fixture strings for reflection, obfuscation, generated code and shared library namespaces to measure false-positive behavior. | Planned |
| 166 | APK native library awareness | List native library files and architecture as static inventory only; do not claim native libraries were analyzed or executed without a working parser. | Planned |
| 167 | APK signer lineage behavior | Define rotation support against Android signing lineage formats; keep UNKNOWN when lineage cannot be validated and test downgrade candidates. | Planned |
| 168 | APK split-package context | Handle split APKs and bundle-derived sets as a coherent installation where possible; otherwise warn that one file is incomplete context. | Planned |
| 169 | APK privacy diff missing-baseline behavior | Test missing, corrupt or mismatched baselines and keep added/removed differences unknown rather than manufacturing a clean result. | Planned |
| 170 | APK report machine-readable schema | Version report JSON, reject unknown required semantics, include APK/catalog/tool hashes, and provide backward-compatibility fixtures. | Planned |

## Metadata scrubber and file sharing

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 171 | PNG CRC and ordering corpus | Cover critical/ancillary ordering, CRC errors, IDAT contiguity, IEND placement, trailing bytes and output reparse. | Partially covered; add canonical vectors |
| 172 | WebP RIFF size consistency | Test declared container size, chunk sizes, odd-byte padding, feature flags and truncation; reject outputs that cannot be reparsed. | Partially covered |
| 173 | JPEG marker and scan conformance | Build canonical baseline/progressive fixtures with APP markers, restart markers, byte stuffing, and truncated scan data. | Partially covered |
| 174 | Scrub idempotence | Run each supported format twice and assert second-pass byte-equivalence or a documented normalization result with no false removal claims. | Planned |
| 175 | Metadata preservation matrix | Confirm image decode payloads/critical color profiles remain valid where promised; explicitly report removed and unrecognized metadata categories. | Planned |
| 176 | Atomic destination replacement | Test output provider failures and replacement semantics; never delete an existing destination before verified output is ready. | Planned |
| 177 | Share URI grant lifecycle | Test that only the cleaned output URI receives a read grant and that grants/source refs are not retained after failed share launches. | Planned |
| 178 | Unsupported file format handling | Test HEIC, TIFF, PDF, video and generic binaries return a clear unsupported result and are not mislabeled as cleaned. | Planned |
| 179 | Sensitive visual content distinction | Clearly distinguish metadata removal from face/license-plate/location-in-image detection; no pixel-level redaction claims without real processing. | Planned |
| 180 | File import size and content-type mismatch | Test provider MIME lies, extension mismatch, huge streams and truncated input using byte limits before copying full data into memory. | Planned |

## Tracker intelligence and app recommendations

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 181 | Tracker schema v2 source review date | Add a migration for per-entry source-review date, source-role, reviewed-by workflow and evidence expiration without fabricating historical reviews. | Requires schema migration |
| 182 | Tracker evidence age report | Report stale individual evidence URLs and IDs; unknown source dates remain unknown and cannot be passed off as current. | Planned |
| 183 | Tracker vendor/domain attribution taxonomy | Distinguish first-party, vendor-owned, shared CDN, hosting, measurement and unknown endpoints; document source for every category assignment. | Research and review required |
| 184 | Tracker confidence calibration fixtures | Build labeled positive/negative fixtures and quantify precision/recall by indicator type before changing confidence tiers. | Needs reviewed dataset |
| 185 | Tracker feed quarantine | Store untrusted feed candidates separately from active catalogue; schema validation and evidence review must succeed before promotion. | Planned |
| 186 | Tracker signature retirement | Define deprecation reason, replacement ID and removal date; old IDs remain traceable in reports after retirement. | Planned |
| 187 | Tracker update diff report | Generate stable machine-readable catalog before/after diffs, including evidence changes, confidence changes, retired IDs and rule impact. | Planned |
| 188 | App alternative trade-off schema | Require migration, compatibility, account portability, telemetry caveats, platform support and evidence dates in catalogue entries. | Planned |
| 189 | App alternative destination health check | Validate links only in a controlled network job with request disclosure; do not fetch arbitrary URLs from the user's device automatically. | Planned |
| 190 | App alternative review provenance | Store per-entry reviewer/date and link to official primary sources; stale entries remain visible but explicitly labeled. | Planned |

## Web and backend privacy boundaries

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 191 | Frontend fetch inventory test | Enumerate every fetch/XHR destination in the web app and fail tests if a new outbound host appears without an explicit allowlist update. | Planned |
| 192 | Imported checkpoint no-upload test | Instrument browser fetch and service worker interactions while verifying checkpoints; prove fixture bytes are not uploaded or persisted. | Planned |
| 193 | Browser memory lifetime guidance | Clear in-memory imported bytes/results on reset and document that JavaScript strings cannot be reliably zeroized. | Planned |
| 194 | Clipboard disclosure test | Label copy actions, minimize copied sensitive data and test that reset clears result views even though clipboard contents are OS-managed. | Planned |
| 195 | CSP deployment verification | Inspect actual served headers and build output; don't infer CSP from source config alone. | Requires deployment access |
| 196 | API body size boundaries | Add per-route maximum request bytes, nesting limits and schema validation tests for oversized and deeply nested JSON. | Planned |
| 197 | Backend request throttling | Specify per-client and per-token limits; test bursts and ensure rate limiting does not leak account existence. | Planned |
| 198 | Backend retention and deletion map | Trace database records, backups, logs and caches; tests verify each deletion promise or clearly narrow it. | Requires data inventory |
| 199 | Service-worker cache audit | Prove private checkpoint/profile data cannot enter precache/runtime cache and purge relevant state when the user resets the app. | Planned |
| 200 | Web dependency and license SBOM | Produce reproducible npm dependency/licenses and vulnerable-package reports in CI without automatic dependency upgrades. | Planned |

## Windows privacy auditor safety

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 201 | Windows read-only audit syscall test | Mock registry, network adapter and PowerShell observations; assert audit-only commands never invoke mutation helpers. | Planned |
| 202 | Windows firewall partial failure rollback | Inject failure at each mutation and restore step; show exactly which rules were restored and which remain unknown. | Planned |
| 203 | Windows restore re-read verification | After a rollback, query actual policy again rather than reporting success based solely on command exit status. | Planned |
| 204 | Windows registry policy provenance | Differentiate absent value, default, explicit value, access denied and conflict with Group Policy/MDM sources. | Planned |
| 205 | Windows command execution allowlist | Use absolute executable paths where feasible, argument arrays, bounded output, timeouts and explicit exit-code classification. | Planned |
| 206 | Windows proxy/DNS evidence scope | Report per-user proxy, WinHTTP proxy, per-interface resolver and VPN state separately with unsupported browser-specific assumptions visible. | Planned |
| 207 | Windows report seeded-secret test | Inject fake account names, paths, tokens and proxy credentials into collector data; ensure default report redaction removes them. | Planned |
| 208 | Windows elevation checks | Explain required rights before actions and fail before partial mutations when privilege prerequisites are absent. | Planned |
| 209 | Windows rollback artifact retention | Define where rollback snapshots live, protect them from casual disclosure, validate schema, and make deletion/export explicit. | Planned |
| 210 | Windows native-runner coverage gate | Require Windows-hosted CI for PowerShell/registry semantics and visibly separate cross-compile checks from runtime validation. | Existing workflow; audit acceptance semantics |

## Release engineering and user safety

| # | Milestone | Deliverable and acceptance criteria | Status |
|---:|---|---|---|
| 211 | Reproducible dependency inventory | Generate Gradle, Cargo, Go and npm SBOMs with lockfile hashes and license data; attach artifacts to CI without silent upgrades. | Planned |
| 212 | Vulnerability exception ledger | Every accepted advisory has owner, expiry, impact analysis and removal trigger; expired exceptions fail CI. | Planned |
| 213 | Build provenance manifest | Emit source commit, toolchain versions, dependency lock hashes, build mode and artifact SHA-256 for release artifacts. | Planned |
| 214 | Reproducible Android build investigation | Build independently and compare artifact hashes; document timestamps/signature differences without claiming determinism before byte comparison. | Planned |
| 215 | Privacy regression seeded-secret scanner | Inject synthetic unique tokens and search test logs, exported reports, screenshots/artifacts and crash messages for leakage. | Planned |
| 216 | Local-only network assertion suite | Instrument network calls around features labeled local-only and fail if user-selected content is transmitted. | Planned |
| 217 | Backup/data extraction verification | Inspect actual manifest/API behavior and test backup/restore on supported Android versions for baseline/history/key consistency. | Device-dependent |
| 218 | Permission rationale coverage | Map every sensitive permission request or Settings handoff to purpose, denial handling, and non-bypass behavior. | Planned |
| 219 | Privacy warning accessibility | Use semantic labels, focus order, TalkBack, large text and contrast checks for redaction/uncertainty/irreversible-action warnings. | Device/UI validation |
| 220 | Release gate from evidence | Generate release report from latest-head CI, open critical issues, entitlement requirements, legal-review state, and platform test coverage; fail releases on missing sign-offs. | Planned |

## Current integrity gate

Before continuing past this register, the existing main-branch red tests must be fixed and the affected Android, Rust and Web suites must pass on the same current head. Do not treat older green runs from a different commit as evidence for the current head.
