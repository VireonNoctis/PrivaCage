#!/usr/bin/env bash
set -euo pipefail

: "${PERFORMANCE_BASELINE_SHA:?Set PERFORMANCE_BASELINE_SHA}"
: "${PERFORMANCE_BASELINE_DIR:?Set PERFORMANCE_BASELINE_DIR}"
: "${PERFORMANCE_RESULTS_DIR:?Set PERFORMANCE_RESULTS_DIR}"
: "${GITHUB_WORKSPACE:?Expected GitHub workspace}"

ROOT="$GITHUB_WORKSPACE"
BASELINE="$PERFORMANCE_BASELINE_DIR"
RESULTS="$PERFORMANCE_RESULTS_DIR"
HEAD_SHA="$(git -C "$ROOT" rev-parse HEAD)"
mkdir -p "$RESULTS/baseline" "$RESULTS/head"

# Reuse one dependency cache on the same runner; the implementation and benchmark
# workloads remain sequential to avoid CPU contention between samples.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$RUNNER_TEMP/privacage-cargo-target}"

run_rust_benchmark() {
    local label="$1"
    local workspace="$2"
    local log="$RESULTS/$label/rust-apk-scan.log"
    local jsonl="$RESULTS/$label/rust-apk-scan.jsonl"

    echo "::group::Rust APK scan benchmark ($label)"
    cargo bench --manifest-path "$workspace/shared/rust/tracker-intelligence/Cargo.toml" \
        --bench apk_scan 2>&1 | tee "$log"
    sed -n 's/^PERF_JSON://p' "$log" > "$jsonl"
    if [[ "$(wc -l < "$jsonl")" -ne 3 ]]; then
        echo "Expected three Rust APK scan measurements for $label." >&2
        exit 1
    fi
    echo "::endgroup::"
}

run_dns_benchmark() {
    local label="$1"
    local workspace="$2"
    local log="$RESULTS/$label/dns.log"
    local report="$workspace/android-core/build/reports/performance/dns-benchmark.json"

    echo "::group::DNS benchmark ($label)"
    gradle --no-daemon --console=plain --rerun-tasks \
        --project-dir "$workspace/android-app" :android-core:performanceTest 2>&1 | tee "$log"
    if [[ ! -s "$report" ]]; then
        echo "DNS benchmark did not create its JSON report: $report" >&2
        exit 1
    fi
    cp "$report" "$RESULTS/$label/dns.json"
    echo "::endgroup::"
}

run_startup_benchmark() {
    local label="$1"
    local workspace="$2"
    local output="$RESULTS/$label/startup.json"
    local build_outputs="$workspace/android-app/performance-macrobenchmark/build/outputs/connected_android_test_additional_output"
    local report=""

    echo "::group::Android cold-start benchmark ($label)"
    adb shell pm clear org.privacage.android >/dev/null 2>&1 || true
    rm -rf "$build_outputs"

    gradle --no-daemon --console=plain --rerun-tasks \
        --project-dir "$workspace/android-app" \
        :performance-macrobenchmark:connectedBenchmarkAndroidTest \
        -Pandroid.testInstrumentationRunnerArguments.androidx.benchmark.suppressErrors=EMULATOR

    if [[ -d "$build_outputs" ]]; then
        report="$(find "$build_outputs" -type f -name '*benchmarkData.json' -print -quit)"
    fi
    if [[ -z "$report" || ! -s "$report" ]]; then
        echo "Macrobenchmark completed without a benchmarkData.json report for $label." >&2
        find "$workspace/android-app/performance-macrobenchmark/build/outputs" -type f | head -80 >&2 || true
        exit 1
    fi
    cp "$report" "$output"
    echo "Saved startup measurements to $output"
    echo "::endgroup::"
}

run_rust_benchmark baseline "$BASELINE"
run_rust_benchmark head "$ROOT"
run_dns_benchmark baseline "$BASELINE"
run_dns_benchmark head "$ROOT"
run_startup_benchmark baseline "$BASELINE"
run_startup_benchmark head "$ROOT"

python "$ROOT/.github/scripts/compare-performance.py" \
    --results "$RESULTS" \
    --baseline "$PERFORMANCE_BASELINE_SHA" \
    --head "$HEAD_SHA" \
    --output "$RESULTS/comparison.md"

cat "$RESULTS/comparison.md"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    cat "$RESULTS/comparison.md" >> "$GITHUB_STEP_SUMMARY"
fi
