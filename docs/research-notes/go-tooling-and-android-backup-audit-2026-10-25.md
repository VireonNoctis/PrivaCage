# Go tooling migration and Android backup audit — 25 October 2026

## Scope and decision

The repository's active Python surface consisted of four production scripts and four Python unittest modules: tracker schema/freshness validation, the tracker review report, Android manifest backup policy, Android sensitive-permission policy, Gradle telemetry-SDK marker checks, and their regression tests. These are repository/CI tools, not Android runtime components.

**Decision: Go, using only the standard library.** The tools need deterministic JSON validation, calendar-date arithmetic, HTTPS URL syntax checks, Android XML inspection, recursive Gradle-file scanning and command-line exit codes. Go's standard packages cover those operations; `encoding/json.Decoder.DisallowUnknownFields` supports strict schema decoding, `encoding/xml` parses Android manifests, `time.Parse` validates date layouts, and the built-in `testing` package runs focused regression tests. The GitHub Actions setup-go action provides a pinned toolchain for CI. These are capability matches, not a claim that Go code is automatically safer than Python.

Sources:
- Go JSON decoder and unknown-field rejection: https://pkg.go.dev/encoding/json#Decoder.DisallowUnknownFields
- Go XML parser: https://pkg.go.dev/encoding/xml
- Go date parsing: https://pkg.go.dev/time#Parse
- Official Go testing tutorial: https://go.dev/doc/tutorial/add-a-test
- GitHub Actions Go setup: https://github.com/actions/setup-go

## Migrated behavior and verification contract

The Go module at `shared/go/pcage-tools/` exposes four commands:

- `validate-tracker`: schema-version 1 field/type validation; exact defined fields; stable unique IDs; normalized hostname indicators; valid terminal SDK wildcards; unique HTTPS evidence URLs without URL credentials; canonical dates; and an optional evidence-age gate.
- `tracker-report`: current, due-soon, overdue and future-dated review states in Markdown or JSON. It reports human-maintained review dates; it does not fetch evidence URLs or certify their truth.
- `validate-android-backup`: require an explicit `android:allowBackup="false"` declaration in the single source-manifest application element.
- `validate-android-privacy`: reject the project's currently unapproved sensitive Android permission set and known analytics/ad/crash-reporting dependency markers in Gradle build files.

Go tests replace the four Python test modules. CI runs the Go tests and calls the actual commands. The code does not download tracker data, upload manifests, or call third-party services. The catalog remains curated JSON, and a successful schema check does not prove an indicator is accurate or safe to block.

## Important research finding: Android backup configuration is not a device-level guarantee

Android's current Auto Backup documentation states that, for apps targeting Android 12 (API 31) or later, `android:allowBackup="false"` may disable cloud backup/restore but may not disable device-to-device transfers on some device manufacturers' devices. The same documentation distinguishes the legacy `fullBackupContent` rules for Android 11 and lower from `dataExtractionRules` for Android 12 and higher, and notes that cloud backup and device-to-device transfer have distinct rule sections.

Source: https://developer.android.com/identity/data/autobackup

**What the automated check establishes:** the checked-in source manifest declares the current policy. It does not prove that an OEM's migration flow complies with that policy, that secrets are absent from every backup artifact, or that restore cannot recreate private state. This remains an explicit test gap, not a green check.

### Fix plan for the backup/restore gap

1. Keep the manifest policy gate in CI, and fail if the backup declaration is removed, changed to true, or becomes ambiguous.
2. Before making a device-level privacy claim, test the actual application on Android 11/API 30 and Android 12+/API 31+; include at least one Pixel-class reference device and one Samsung/OEM transfer path where available.
3. Exercise cloud backup/restore and setup-wizard or cable-based device-to-device migration separately. Record OS/build, transport, installation path, and test result; check for both presence and absence of the specific local state expected by the product.
4. Store non-restorable secrets in Android Keystore-backed key material and avoid placing transient/sensitive files in backup-eligible locations. Where backup is needed for non-secret settings, use documented inclusion/exclusion rules for each supported Android version and transfer mode, then verify behavior with an on-device test.
5. Treat a missing or untested path as **unknown**, not as evidence that no data transfers. Keep the limitation visible in release notes until the device matrix has results.

This is partially buildable now (manifest/CI checks); the OEM transfer portion requires real devices or suitable emulators and has not been certified by this code change.

## Next areas worth pursuing

### Signed tracker catalog releases and anti-rollback — before any remote catalog updater

The current validator checks data shape and human-set freshness dates, not publisher authenticity. Before adding a remote updater, package each catalog release in a signed envelope binding the catalog digest, schema version, release sequence/epoch and signing-key ID. Verify the signature before parsing or importing records, and persist the highest accepted epoch so an older-but-valid signed catalog cannot silently roll back trust decisions. Key rotation needs an explicit trust transition and a recovery plan. Do not ship a hard-coded test key as a production trust anchor, and do not enable remote fetching until a maintainer-controlled release signing key and rotation process exist.

Integration: reuse the canonical catalog in `shared/tracker-db/`; add signing/verification vectors and tests to Go tooling or the existing Rust crypto core; verify at the Android import boundary before indicators can be imported. Network transport should remain optional and must not be the authenticity mechanism.

### Cryptographic peer handoff acknowledgements

The owner-key rotation handoff currently relies on an operator acknowledgement after the intended peers have accepted the transition. A future protocol increment could let each receiving device return a signed acknowledgement bound to the transition digest, its device fingerprint and roster revision. The owner would display the exact set of acknowledgements received. Missing acknowledgements must remain visibly pending; a relay receipt alone is not proof the peer imported the roster. This fits the existing sync protocol but requires careful replay, revocation, and recovery semantics before UI claims are made.

### Local breach-exposure lookup

A local-only breach checker could reduce disclosure to a third-party lookup service, but dataset licensing, coverage, update cadence and matching protocol must be researched first. Do not build a UI that suggests a negative match means an address has never appeared in a breach. Prefer a documented, refreshable local dataset or a privacy-preserving protocol with explicitly explained residual leakage.

## Research and release hygiene

- Keep validators deterministic and offline; do not let CI automatically promote review-only trackers to active.
- Treat evidence freshness as a human review reminder, not a source-truth score.
- Maintain one supported Go module and keep third-party dependencies at zero unless a concrete requirement justifies one.
- After migration, search all tracked docs and workflows for stale Python command paths and remove the old Python implementation and tests.
- Keep full Android device migration, independent crypto review and runtime traffic coverage as separate verification gates.
