#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEMP="$(mktemp -d)"
trap 'rm -rf "$TEMP"' EXIT

SDK="$TEMP/sdk"
RESULTS="$TEMP/results"
mkdir -p "$SDK/emulator" "$SDK/platform-tools" "$RESULTS"

cat > "$SDK/emulator/emulator" <<'FAKE_EMULATOR'
#!/usr/bin/env bash
case "$1" in
    -version) printf 'Android emulator version 35.2.10\n' ;;
    -accel-check) printf 'accel: 0\n' ;;
    *) printf 'unexpected emulator arguments: %s\n' "$*" >&2; exit 2 ;;
esac
FAKE_EMULATOR

cat > "$SDK/platform-tools/adb" <<'FAKE_ADB'
#!/usr/bin/env bash
case "$*" in
    version) printf 'Android Debug Bridge version 1.0.41\n' ;;
    "shell getprop ro.build.version.sdk") printf '35\r\n' ;;
    "shell getprop ro.product.model") printf 'Pixel Runner\r\n' ;;
    "shell getprop sys.boot_completed") printf '1\r\n' ;;
    "shell getprop "*) printf 'test-value\r\n' ;;
    "shell wm size") printf 'Physical size: 1080x2400\n' ;;
    "shell wm density") printf 'Physical density: 420\n' ;;
    *) printf 'unexpected adb arguments: %s\n' "$*" >&2; exit 2 ;;
esac
FAKE_ADB

chmod +x "$SDK/emulator/emulator" "$SDK/platform-tools/adb"
export ANDROID_SDK_ROOT="$SDK"
export ANDROID_HOME="$SDK"
export PERFORMANCE_RESULTS_DIR="$RESULTS"

bash "$ROOT/.github/scripts/capture-performance-environment.sh" host
OUTPUT="$RESULTS/environment.txt"
grep -Fx 'tool.emulator=Android emulator version 35.2.10' "$OUTPUT"
grep -Fx 'tool.adb=Android Debug Bridge version 1.0.41' "$OUTPUT"
if grep -Fq '\n' "$OUTPUT"; then
    echo "environment capture wrote literal backslash-n sequences" >&2
    exit 1
fi

bash "$ROOT/.github/scripts/capture-performance-environment.sh" emulator
grep -Fx 'emulator.ro.build.version.sdk=35' "$OUTPUT"
grep -Fx 'emulator.ro.product.model=Pixel Runner' "$OUTPUT"
grep -Fx 'emulator.sys.boot_completed=1' "$OUTPUT"
grep -Fx 'emulator.screen_size=Physical size: 1080x2400' "$OUTPUT"
if grep -Fq $'\r' "$OUTPUT"; then
    echo "environment capture retained carriage returns" >&2
    exit 1
fi

echo "Performance environment capture tests passed."
