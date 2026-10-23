import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "shared" / "scripts" / "validate-android-backup.py"
SPEC = importlib.util.spec_from_file_location("validate_android_backup", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

MANIFEST = Path(__file__).resolve().parents[1] / "android-app" / "app" / "src" / "main" / "AndroidManifest.xml"


class AndroidBackupPolicyTests(unittest.TestCase):
    def test_repository_manifest_explicitly_disables_backup(self):
        self.assertEqual(validator.validate_manifest(MANIFEST), [])
        self.assertEqual(validator.main(["--manifest", str(MANIFEST)]), 0)

    def test_allow_backup_true_is_rejected(self):
        xml = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="true"/></manifest>'
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".xml") as handle:
            handle.write(xml)
            handle.flush()
            self.assertTrue(any("allowBackup" in error for error in validator.validate_manifest(Path(handle.name))))

    def test_missing_allow_backup_is_rejected(self):
        xml = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:label="PrivaCage"/></manifest>'
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".xml") as handle:
            handle.write(xml)
            handle.flush()
            self.assertTrue(any("explicitly declare" in error for error in validator.validate_manifest(Path(handle.name))))

    def test_manifest_without_application_is_rejected(self):
        xml = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"/>'
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".xml") as handle:
            handle.write(xml)
            handle.flush()
            self.assertTrue(any("<application>" in error for error in validator.validate_manifest(Path(handle.name))))

    def test_malformed_manifest_xml_is_reported(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".xml") as handle:
            handle.write("<manifest><application>")
            handle.flush()
            self.assertTrue(any("XML is invalid" in error for error in validator.validate_manifest(Path(handle.name))))


if __name__ == "__main__":
    unittest.main()
