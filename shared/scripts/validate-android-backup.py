#!/usr/bin/env python3
"""Check PrivaCage's declared Android backup posture; not an OEM transfer test."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "android-app" / "app" / "src" / "main" / "AndroidManifest.xml"
ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_ALLOW_BACKUP = f"{{{ANDROID_NS}}}allowBackup"


def validate_manifest(path: Path) -> list[str]:
    """Return policy errors for the source manifest at path."""
    try:
        root = ET.parse(path).getroot()
    except OSError as exc:
        return [f"cannot read manifest {path}: {exc}"]
    except ET.ParseError as exc:
        return [f"manifest XML is invalid in {path}: {exc}"]

    if root.tag != "manifest":
        return ["document root must be <manifest>"]

    applications = root.findall("application")
    if len(applications) != 1:
        return ["manifest must contain exactly one <application> element"]

    value = applications[0].get(ANDROID_ALLOW_BACKUP)
    if value is None:
        return ['<application> must explicitly declare android:allowBackup="false"']
    if value.lower() != "false":
        return ['<application> must set android:allowBackup="false" for the current local-data policy']

    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="path to AndroidManifest.xml",
    )
    args = parser.parse_args(argv)

    errors = validate_manifest(args.manifest)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        f"OK: {args.manifest} explicitly disables Android Auto Backup in the source manifest. "
        "This static check does not prove OEM/device-to-device transfer behavior."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
