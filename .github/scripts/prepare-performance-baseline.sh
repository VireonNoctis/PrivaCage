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

copy_into_baseline() {
    local path="$1"
    mkdir -p "$BASELINE/$(dirname "$path")"
    cp "$ROOT/$path" "$BASELINE/$path"
}

# Install the current flat app/build harness into the historical worktree.
copy_into_baseline "apps/android/settings.gradle.kts"
copy_into_baseline "apps/android/gradle.properties"
copy_into_baseline "apps/android/build.gradle.kts"
copy_into_baseline "apps/android/main/AndroidManifest.xml"
copy_into_baseline "apps/android/test/build.gradle.kts"
copy_into_baseline "apps/android/test/AndroidManifest.xml"
copy_into_baseline "apps/android/test/benchmark/PrivaCageStartupBenchmark.kt"
copy_into_baseline "apps/android/test/dns/DnsPerformanceBenchmarkTest.kt"
mkdir -p "$BASELINE/apps/android/main/res"
cp -R "$ROOT/apps/android/main/res/." "$BASELINE/apps/android/main/res/"

# The baseline predates the flat app layout. Re-home its original app and
# Kotlin/JVM engine source files without copying candidate implementation.
LEGACY_APP="$BASELINE/android-app/app/src/main/kotlin/org/privacage/android"
LEGACY_CORE="$BASELINE/android-core/src/main/kotlin/org/privacage"
if [[ ! -d "$LEGACY_APP" || ! -d "$LEGACY_CORE" ]]; then
    echo "Historical Android application/core sources were not found in the baseline worktree." >&2
    exit 1
fi

mkdir -p "$BASELINE/apps/android/main/interface" "$BASELINE/apps/android/main/sync"
find "$LEGACY_APP" -maxdepth 1 -type f -name '*.kt' -exec cp {} "$BASELINE/apps/android/main/interface/" \;
if [[ -d "$LEGACY_APP/sync" ]]; then
    find "$LEGACY_APP/sync" -maxdepth 1 -type f -name '*.kt' -exec cp {} "$BASELINE/apps/android/main/sync/" \;
fi

for feature in audit crypto dns metadata; do
    source_dir="$LEGACY_CORE/$feature"
    destination="$BASELINE/apps/android/main/$feature"
    if [[ -d "$source_dir" ]]; then
        mkdir -p "$destination"
        find "$source_dir" -maxdepth 1 -type f -name '*.kt' -exec cp {} "$destination/" \;
    fi
done

echo "Baseline worktree: $BASELINE"
echo "Baseline commit: $PERFORMANCE_BASELINE_SHA"
echo "Benchmark harness copied from candidate commit: $(git -C "$ROOT" rev-parse HEAD)"
