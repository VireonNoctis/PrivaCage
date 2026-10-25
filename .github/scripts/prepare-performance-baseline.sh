#!/usr/bin/env bash
set -euo pipefail

: "${PERFORMANCE_BASELINE_SHA:?Set PERFORMANCE_BASELINE_SHA to the pre-optimization commit}"
: "${PERFORMANCE_BASELINE_DIR:?Set PERFORMANCE_BASELINE_DIR}"
: "${GITHUB_WORKSPACE:?Expected GitHub workspace}"

ROOT="$GITHUB_WORKSPACE"
BASELINE="$PERFORMANCE_BASELINE_DIR"

git cat-file -e "${PERFORMANCE_BASELINE_SHA}^{commit}" 2>/dev/null || \
    git fetch --no-tags origin "$PERFORMANCE_BASELINE_SHA"

if [[ -e "$BASELINE" ]]; then
    git worktree remove --force "$BASELINE" 2>/dev/null || rm -rf "$BASELINE"
fi

git worktree add --detach "$BASELINE" "$PERFORMANCE_BASELINE_SHA"

# The pre-optimization commit intentionally lacks benchmark-only files. Copy the
# identical harness/configuration into it while keeping the code under test pinned
# to the baseline commit.
copy_into_baseline() {
    local path="$1"
    mkdir -p "$BASELINE/$(dirname "$path")"
    cp "$ROOT/$path" "$BASELINE/$path"
}

copy_into_baseline "android-core/build.gradle.kts"
copy_into_baseline "android-core/src/test/kotlin/org/privacage/dns/DnsPerformanceBenchmarkTest.kt"
copy_into_baseline "shared/rust/tracker-intelligence/Cargo.toml"
copy_into_baseline "shared/rust/tracker-intelligence/benches/apk_scan.rs"
copy_into_baseline "android-app/settings.gradle.kts"
copy_into_baseline "android-app/app/build.gradle.kts"
copy_into_baseline "android-app/app/src/main/AndroidManifest.xml"

mkdir -p "$BASELINE/android-app/performance-macrobenchmark"
cp -R "$ROOT/android-app/performance-macrobenchmark/." \
    "$BASELINE/android-app/performance-macrobenchmark/"

echo "Baseline worktree: $BASELINE"
echo "Baseline commit: $PERFORMANCE_BASELINE_SHA"
echo "Benchmark harness copied from candidate commit: $(git -C "$ROOT" rev-parse HEAD)"
