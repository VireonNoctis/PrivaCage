#!/usr/bin/env python3
"""Guard PrivaCage's own Android permission and telemetry-SDK baseline."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "android-app" / "app" / "src" / "main" / "AndroidManifest.xml"
DEFAULT_ANDROID_DIR = ROOT / "android-app"
ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_NAME = f"{{{ANDROID_NS}}}name"

# These permissions are not part of PrivaCage's current product contract. Adding one
# requires an explicit design review and a user-visible purpose; this is not a universal
# statement that these permissions are never legitimate for any future feature.
SENSITIVE_PERMISSIONS = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.CAMERA",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECORD_AUDIO",
}

# Dependency identifiers for common analytics, ad attribution, and crash-reporting SDKs.
# This narrow static check does not prove the absence of equivalent hand-written code.
TELEMETRY_DEPENDENCY_MARKERS = (
    "firebase-analytics",
    "firebase-crashlytics",
    "play-services-ads",
    "sentry-android",
    "bugsnag",
    "appsflyer",
    "adjust-android",
    "mixpanel",
    "amplitude-android",
    "segment-analytics",
)


def validate_manifest(path: Path) -> list[str]:
    """Return policy errors for sensitive permissions declared by the app."""
    try:
        root = ET.parse(path).getroot()
    except OSError as exc:
        return [f"cannot read manifest {path}: {exc}"]
    except ET.ParseError as exc:
        return [f"manifest XML is invalid in {path}: {exc}"]

    if root.tag != "manifest":
        return ["document root must be <manifest>"]

    declared = {
        element.get(ANDROID_NAME, "")
        for element in root
        if element.tag in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}
    }
    violations = sorted(declared & SENSITIVE_PERMISSIONS)
    return [f"unreviewed sensitive permission declared: {permission}" for permission in violations]


def validate_android_dependencies(android_dir: Path) -> list[str]:
    """Reject known analytics/ad/crash SDK identifiers in Android Gradle build files."""
    if not android_dir.is_dir():
        return [f"Android project directory does not exist: {android_dir}"]

    build_files = sorted(
        path for path in android_dir.rglob("*")
        if path.is_file() and path.name.endswith((".gradle", ".gradle.kts"))
    )
    errors: list[str] = []
    for path in build_files:
        try:
            content = path.read_text(encoding="utf-8").lower()
        except OSError as exc:
            errors.append(f"cannot read Gradle file {path}: {exc}")
            continue
        for marker in TELEMETRY_DEPENDENCY_MARKERS:
            if marker in content:
                errors.append(f"known telemetry SDK marker {marker!r} found in {path}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--android-dir", type=Path, default=DEFAULT_ANDROID_DIR)
    args = parser.parse_args(argv)

    errors = validate_manifest(args.manifest) + validate_android_dependencies(args.android_dir)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        "OK: no unreviewed sensitive permissions or known analytics/ad/crash SDK identifiers "
        "were found in the checked Android manifest and Gradle files. This static check "
        "does not prove the absence of hand-written telemetry or privileged OS/OEM collection."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
