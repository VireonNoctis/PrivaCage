import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "shared" / "scripts" / "validate-signatures.py"
SPEC = importlib.util.spec_from_file_location("validate_signatures", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def valid_document():
    return {
        "schema_version": 1,
        "updated_at": "2026-10-21",
        "entries": [{
            "id": "example-analytics-sdk",
            "name": "Example Analytics SDK",
            "category": "analytics",
            "indicators": {
                "domains": ["metrics.example.org"],
                "sdk_patterns": ["org.example.analytics.**"],
            },
            "confidence": "medium",
            "status": "active",
            "last_verified": "2026-10-20",
            "evidence": [{
                "url": "https://docs.example.org/analytics-sdk",
                "description": "Example test fixture only; not a real tracker signature.",
            }],
        }],
    }


class ValidateSignaturesTests(unittest.TestCase):
    def test_empty_database_is_valid(self):
        document = {"schema_version": 1, "updated_at": "2026-10-21", "entries": []}
        self.assertEqual(validator.validate_database(document), [])

    def test_valid_entry_is_accepted(self):
        self.assertEqual(validator.validate_database(valid_document()), [])

    def test_duplicate_ids_are_rejected(self):
        document = valid_document()
        document["entries"].append(dict(document["entries"][0]))
        self.assertTrue(any("duplicate id" in error for error in validator.validate_database(document)))

    def test_non_https_evidence_is_rejected(self):
        document = valid_document()
        document["entries"][0]["evidence"][0]["url"] = "http://docs.example.org/analytics-sdk"
        self.assertTrue(any("must use HTTPS" in error for error in validator.validate_database(document)))

    def test_url_syntax_is_rejected_as_a_domain(self):
        document = valid_document()
        document["entries"][0]["indicators"]["domains"] = ["https://metrics.example.org/path"]
        self.assertTrue(any("valid hostname" in error for error in validator.validate_database(document)))

    def test_invalid_calendar_date_is_rejected(self):
        document = valid_document()
        document["entries"][0]["last_verified"] = "2026-02-30"
        self.assertTrue(any("valid calendar date" in error for error in validator.validate_database(document)))

    def test_unknown_fields_are_rejected(self):
        document = valid_document()
        document["entries"][0]["trusted"] = True
        self.assertTrue(any("fields must be exactly" in error for error in validator.validate_database(document)))

    def test_repository_database_passes_cli(self):
        database = SCRIPT.parents[1] / "tracker-db" / "signatures.json"
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
            json.dump(json.loads(database.read_text(encoding="utf-8")), handle)
            handle.flush()
            self.assertEqual(validator.main(["--file", handle.name]), 0)


if __name__ == "__main__":
    unittest.main()
