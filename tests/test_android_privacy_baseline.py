import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "shared" / "scripts" / "validate-android-privacy.py"
SPEC = importlib.util.spec_from_file_location("validate_android_privacy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

MANIFEST = ROOT / "android-app" / "app" / "src" / "main" / "AndroidManifest.xml"
ANDROID_DIR = ROOT / "android-app"


class AndroidPrivacyBaselineTests(unittest.TestCase):
    def test_repository_manifest_has_no_unreviewed_sensitive_permissions(self):
        self.assertEqual(validator.validate_manifest(MANIFEST), [])

    def test_sensitive_permission_is_rejected(self):
        xml = (
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            '<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>'
            '<application android:allowBackup="false"/></manifest>'
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".xml") as handle:
            handle.write(xml)
            handle.flush()
            errors = validator.validate_manifest(Path(handle.name))
        self.assertTrue(any("ACCESS_FINE_LOCATION" in error for error in errors))

    def test_known_analytics_sdk_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            gradle = Path(directory) / "app.gradle.kts"
            gradle.write_text(
                'dependencies { implementation("com.google.firebase:firebase-analytics") }',
                encoding="utf-8",
            )
            errors = validator.validate_android_dependencies(Path(directory))
        self.assertTrue(any("firebase-analytics" in error for error in errors))

    def test_repository_gradle_files_have_no_known_telemetry_sdk_markers(self):
        self.assertEqual(validator.validate_android_dependencies(ANDROID_DIR), [])

    def test_missing_android_directory_is_reported(self):
        errors = validator.validate_android_dependencies(ROOT / "does-not-exist")
        self.assertTrue(any("does not exist" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
