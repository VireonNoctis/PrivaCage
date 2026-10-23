import importlib.util
import json
import tempfile
import unittest
from datetime import date
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

    def test_alternate_analytics_endpoint_remains_review_only(self):
        database = SCRIPT.parents[1] / "tracker-db" / "signatures.json"
        document = json.loads(database.read_text(encoding="utf-8"))
        entry = next(item for item in document["entries"] if item["id"] == "analytics-google-collection")
        self.assertEqual(entry["confidence"], "medium")
        self.assertEqual(entry["status"], "review")


    def test_new_collection_signatures_have_official_evidence(self):
        database = SCRIPT.parents[1] / "tracker-db" / "signatures.json"
        document = json.loads(database.read_text(encoding="utf-8"))
        by_id = {item["id"]: item for item in document["entries"]}

        expected = {
            "microsoft-clarity-collection": ("www.clarity.ms", "https://learn.microsoft.com/"),
            "posthog-hosted-event-capture": ("us.i.posthog.com", "https://posthog.com/docs/"),
            "google-ads-measurement-endpoints": ("googleadservices.com", "https://developers.google.com/"),
            "pinterest-tag-conversion": ("ct.pinterest.com", "https://developers.pinterest.com/docs/"),
        }
        for entry_id, (domain, evidence_prefix) in expected.items():
            with self.subTest(entry_id=entry_id):
                entry = by_id[entry_id]
                self.assertIn(domain, entry["indicators"]["domains"])
                self.assertTrue(any(source["url"].startswith(evidence_prefix) for source in entry["evidence"]))
                self.assertEqual(entry["status"], "active")

    def test_broad_doubleclick_indicator_remains_review_only(self):
        database = SCRIPT.parents[1] / "tracker-db" / "signatures.json"
        document = json.loads(database.read_text(encoding="utf-8"))
        entry = next(item for item in document["entries"] if item["id"] == "google-floodlight-doubleclick")
        self.assertEqual(entry["status"], "review")
        self.assertEqual(entry["confidence"], "medium")
        self.assertIn("doubleclick.net", entry["indicators"]["domains"])


    def test_recent_evidence_passes_freshness_gate(self):
        document = valid_document()
        document["entries"][0]["last_verified"] = "2026-10-20"
        self.assertEqual(
            validator.validate_database(document, max_age_days=180, today=date(2026, 10, 23)),
            [],
        )

    def test_stale_evidence_fails_freshness_gate(self):
        document = valid_document()
        document["entries"][0]["last_verified"] = "2026-04-01"
        errors = validator.validate_database(document, max_age_days=180, today=date(2026, 10, 23))
        self.assertTrue(any("evidence review is required" in error for error in errors))

    def test_future_verification_date_fails_freshness_gate(self):
        document = valid_document()
        document["entries"][0]["last_verified"] = "2026-10-24"
        errors = validator.validate_database(document, max_age_days=180, today=date(2026, 10, 23))
        self.assertTrue(any("must not be in the future" in error for error in errors))

    def test_nonpositive_freshness_window_is_rejected(self):
        self.assertTrue(any(
            "max_age_days must be a positive integer" in error
            for error in validator.validate_database(valid_document(), max_age_days=0, today=date(2026, 10, 23))
        ))


if __name__ == "__main__":
    unittest.main()
