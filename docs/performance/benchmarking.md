# PrivaCage performance benchmarks

The `performance-comparison` job in the existing Android app/DNS validation workflow compares the pre-optimization snapshot `7649a85dede79c0decf33426655dc246f9c18cc6` with the PR head on the same CI runner. It uploads raw inputs and a Markdown/JSON comparison artifact. The job is a measurement tool, not a timing-based CI gate: no arbitrary hard performance thresholds are enforced.

## Workloads

- **Android startup:** AndroidX Macrobenchmark cold-starts the release-like `benchmark` build type for 10 iterations and reports `timeToInitialDisplayMs` median and p95. This measures when the first screen is rendered, not when every optional background task has completed.
- **DNS trie build:** constructs the policy trie from 10,002 rules.
- **DNS policy lookup:** repeatedly evaluates a valid DNS question against that policy.
- **Blocked DNS packet:** runs a valid IPv4/UDP DNS query through the packet processor and builds the refusal response.
- **Rust APK scan:** scans deterministic synthetic ZIP/DEX containers with 8, 32, and 64 MiB DEX payloads. It reports median/p95 elapsed time and MiB/s. The fixture is designed to exercise whole-file hashing, ZIP reads, DEX string extraction, and indicator matching; it does not model the signing block or a fully valid binary Android manifest.

## Run locally

From the repository root:

```sh
cargo bench --manifest-path shared/rust/tracker-intelligence/Cargo.toml --bench apk_scan
```

For DNS microbenchmarks:

```sh
gradle --no-daemon --project-dir android-app :android-core:performanceTest
```

For startup timing, connect a physical Android device (API 28 or newer), keep the screen on, and run:

```sh
gradle --no-daemon --project-dir android-app :performance-macrobenchmark:connectedBenchmarkAndroidTest
```

The target app's `benchmark` build variant is non-debuggable and built from the app's release build type. The separate Macrobenchmark test runner is debuggable, which is normal for test instrumentation. Startup benchmarking requires a profileable APK and ProfileInstaller; the app manifest declares `<profileable android:shell="true" />` for this measurement. Profileable does not enable app debugging.

## Reading results correctly

The automated A/B workflow uses a GitHub-hosted x86_64 Android emulator because no physical-device farm is provisioned in this repository. It explicitly allows the benchmark library's emulator warning so the test can produce a relative comparison. **Those startup timings are not production-device timing claims.** Android recommends physical devices for representative startup numbers. Use the local physical-device command before making user-facing absolute latency claims.

The DNS and Rust runs are likewise relative measurements for the CI runner. Compare baseline and candidate results from the same workflow run; do not compare absolute numbers across unrelated machines or runner types. The summary defines positive change as faster for latency measurements and higher throughput for throughput measurements. Negative change is a regression in that run. No speedup is claimed until real report values exist.

## Benchmark implementation

- DNS performance tests are tagged `performance`, run through `:android-core:performanceTest`, and excluded from the regular `:android-core:test` task to avoid making normal unit tests slower.
- The baseline worktree receives only the benchmark harness/build configuration. The source code under test remains pinned to the baseline commit.
- Raw JSON and logs are uploaded as the `privacage-performance-comparison` artifact for 30 days. The Markdown summary contains the baseline and candidate commit IDs, measured values, and caveats. The benchmark job runs as part of the existing Android validation workflow for PRs and pushes that touch Android/DNS or benchmark files.
