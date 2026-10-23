import importlib.util
import json
import subprocess
import sys
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "shared" / "scripts" / "tracker-review-report.py"
SPEC = importlib.util.spec_from_file_location("tracker_review_report", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
report_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report_module)


class TrackerReviewReportTests(unittest.TestCase):
    def test_review_states_are_calculated_from_dates(self):
        document = {
            "entries": [
                {"id": "current", "name": "Current", "status": "active", "confidence": "high",
                 "last_verified": "2026-10-01", "evidence": [{"url": "https://docs.example.org"}]},
                {"id": "soon", "name": "Soon", "status": "review", "confidence": "medium",
                 "last_verified": "2026-05-15", "evidence": [{"url": "https://docs.example.org"}]},
                {"id": "old", "name": "Old", "status": "retired", "confidence": "low",
                 "last_verified": "2026-01-01", "evidence": [{"url": "https://docs.example.org"}]},
            ]
        }
        report = report_module.build_report(document, date(2026, 10, 23), 180, 30)
        states = {entry["id"]: entry["review_state"] for entry in report["entries"]}
        self.assertEqual(states["current"], "current")
        self.assertEqual(states["soon"], "due_soon")
        self.assertEqual(states["old"], "overdue")
        self.assertEqual(report["counts"]["overdue"], 1)
        self.assertEqual(report["counts"]["due_soon"], 1)

    def test_repository_report_runs_and_includes_limitations(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--format", "json", "--today", "2026-10-23"],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("limitation", report)
        self.assertGreaterEqual(len(report["entries"]), 15)

    def test_future_review_date_is_flagged(self):
        document = {"entries": [
            {"id": "future", "name": "Future", "status": "active", "confidence": "high",
             "last_verified": "2026-10-24", "evidence": [{"url": "https://docs.example.org"}]}
        ]}
        report = report_module.build_report(document, date(2026, 10, 23), 180, 30)
        self.assertEqual(report["entries"][0]["review_state"], "invalid_future_date")


if __name__ == "__main__":
    unittest.main()
