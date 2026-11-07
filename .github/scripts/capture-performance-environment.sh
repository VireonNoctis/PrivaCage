#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-host}"
RESULTS="${PERFORMANCE_RESULTS_DIR:?PERFORMANCE_RESULTS_DIR must be set}"
OUTPUT="$RESULTS/environment.txt"
ANDROID_SDK_DIR="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -n "$ANDROID_SDK_DIR" ]]; then
    export PATH="$ANDROID_SDK_DIR/emulator:$ANDROID_SDK_DIR/platform-tools:$PATH"
fi
mkdir -p "$RESULTS"

record() {
    local key="$1"
    local value="${2:-unavailable}"
    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    printf '%s=%s\n' "$key" "$value" >> "$OUTPUT"
}

first_line() {
    local output
    if output="$("$@" 2>&1)"; then
        printf '%s\n' "$output" | sed -n '1p'
    else
        printf 'unavailable'
    fi
}

capture_adb_property() {
    local property="$1"
    local value
    if value="$(adb shell getprop "$property" 2>&1)"; then
        record "emulator.$property" "$(printf '%s' "$value" | tr -d '\r')"
    else
        record "emulator.$property" "unavailable"
    fi
}

case "$MODE" in
    host)
        : > "$OUTPUT"
        record "captured_at_utc" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
        record "github.run_id" "${GITHUB_RUN_ID:-unavailable}"
        record "github.run_attempt" "${GITHUB_RUN_ATTEMPT:-unavailable}"
        record "github.event_name" "${GITHUB_EVENT_NAME:-unavailable}"
        record "runner.os" "${RUNNER_OS:-unavailable}"
        record "runner.arch" "${RUNNER_ARCH:-unavailable}"
        record "runner.image_os" "${ImageOS:-unavailable}"
        record "runner.image_version" "${ImageVersion:-unavailable}"
        record "git.head_sha" "$(first_line git rev-parse HEAD)"
        record "git.baseline_sha" "${PERFORMANCE_BASELINE_SHA:-unavailable}"
        record "host.os" "$( . /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}")"
        record "host.kernel" "$(uname -srmo)"
        record "host.cpu_model" "$(awk -F: '/model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)"
        record "host.cpu_cores" "$(nproc)"
        record "host.memory_total_kb" "$(awk '/MemTotal/ {print $2; exit}' /proc/meminfo)"
        record "tool.java" "$(first_line java -version)"
        record "tool.gradle" "$(first_line gradle --version)"
        record "tool.rustc" "$(first_line rustc --version)"
        record "tool.cargo" "$(first_line cargo --version)"
        record "tool.cargo_ndk" "$(first_line cargo ndk --version)"
        record "tool.adb" "$(first_line adb version)"
        record "tool.emulator" "$(first_line emulator -version)"
        record "benchmark.android_api" "${PERFORMANCE_EMULATOR_API_LEVEL:-unavailable}"
        record "benchmark.system_image" "${PERFORMANCE_EMULATOR_TARGET:-unavailable};${PERFORMANCE_EMULATOR_ARCH:-unavailable}"
        record "benchmark.avd_profile" "${PERFORMANCE_EMULATOR_PROFILE:-unavailable}"
        record "benchmark.emulator_cores" "${PERFORMANCE_EMULATOR_CORES:-unavailable}"
        record "benchmark.emulator_ram" "${PERFORMANCE_EMULATOR_RAM_SIZE:-unavailable}"
        record "benchmark.emulator_heap" "${PERFORMANCE_EMULATOR_HEAP_SIZE:-unavailable}"
        record "benchmark.emulator_boot_timeout_seconds" "${PERFORMANCE_EMULATOR_BOOT_TIMEOUT_SECONDS:-unavailable}"
        record "benchmark.emulator_options" "${PERFORMANCE_EMULATOR_OPTIONS:-unavailable}"
        ;;
    emulator)
        if [[ ! -s "$OUTPUT" ]]; then
            printf 'Host environment capture was not completed before emulator capture.\n' > "$OUTPUT"
        fi
        printf '\n[emulator]\n' >> "$OUTPUT"
        capture_adb_property ro.build.version.sdk
        capture_adb_property ro.build.version.release
        capture_adb_property ro.build.fingerprint
        capture_adb_property ro.product.model
        capture_adb_property ro.product.device
        capture_adb_property ro.product.cpu.abi
        capture_adb_property ro.hardware
        capture_adb_property sys.boot_completed
        record "emulator.screen_size" "$(first_line adb shell wm size)"
        record "emulator.screen_density" "$(first_line adb shell wm density)"
        ;;
    *)
        printf 'Usage: %s [host|emulator]\n' "$0" >&2
        exit 2
        ;;
esac
