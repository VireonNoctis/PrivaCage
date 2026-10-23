#!/usr/bin/env python3
"""Generate a local tracker-evidence freshness report; this does not verify sources online."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FILE = ROOT / "shared" / "tracker-db" / "signatures.json"
VALIDATOR = ROOT / "shared" / "scripts" / "validate-signatures.py"


def load_validator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("validate_signatures", VALIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load tracker schema validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_report(document: dict, today: date, interval_days: int, due_soon_days: int) -> dict:
    records = []
    for entry in document["entries"]:
        last_review = date.fromisoformat(entry["last_verified"])
        due_date = last_review + timedelta(days=interval_days)
        age_days = (today - last_review).days
        days_until_due = (due_date - today).days
        if age_days < 0:
            state = "invalid_future_date"
        elif days_until_due < 0:
            state = "overdue"
        elif days_until_due <= due_soon_days:
            state = "due_soon"
        else:
            state = "current"
        records.append({
            "id": entry["id"],
            "name": entry["name"],
            "status": entry["status"],
            "confidence": entry["confidence"],
            "last_verified": last_review.isoformat(),
            "age_days": age_days,
            "review_due": due_date.isoformat(),
            "days_until_due": days_until_due,
            "review_state": state,
            "evidence_urls": [source["url"] for source in entry["evidence"]],
        })
    counts = {state: sum(record["review_state"] == state for record in records)
              for state in ("current", "due_soon", "overdue", "invalid_future_date")}
    return {
        "generated_at": today.isoformat(),
        "review_interval_days": interval_days,
        "due_soon_days": due_soon_days,
        "counts": counts,
        "entries": records,
        "limitation": "Dates measure catalog review freshness only. This report does not fetch sources or prove their accuracy or current endpoint behavior.",
    }


def render_markdown(report: dict) -> str:
    counts = report["counts"]
    lines = [
        "# Tracker evidence review report",
        "",
        f"Generated: {report['generated_at']} | Review interval: {report['review_interval_days']} days",
        "",
        f"- Current: {counts['current']}",
        f"- Due soon: {counts['due_soon']}",
        f"- Overdue: {counts['overdue']}",
        f"- Future-dated / invalid: {counts['invalid_future_date']}",
        "",
        "| State | ID | Status | Confidence | Last reviewed | Review due |",
        "|---|---|---|---|---|---|",
    ]
    for entry in sorted(report["entries"], key=lambda item: (item["review_state"] != "overdue", item["review_due"], item["id"])):
        lines.append(
            f"| {entry['review_state']} | `{entry['id']}` | {entry['status']} | "
            f"{entry['confidence']} | {entry['last_verified']} | {entry['review_due']} |"
        )
    lines += ["", f"**Limit:** {report['limitation']}", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE)
    parser.add_argument("--interval-days", type=int, default=180)
    parser.add_argument("--due-soon-days", type=int, default=30)
    parser.add_argument("--today", type=date.fromisoformat, default=date.today(),
                        help="override current date (YYYY-MM-DD), mainly for tests")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--fail-overdue", action="store_true")
    args = parser.parse_args(argv)
    if args.interval_days <= 0 or args.due_soon_days < 0:
        parser.error("interval-days must be positive and due-soon-days must be non-negative")
    try:
        document = json.loads(args.file.read_text(encoding="utf-8"))
        errors = load_validator().validate_database(document)
        if errors:
            raise ValueError("; ".join(errors))
        report = build_report(document, args.today, args.interval_days, args.due_soon_days)
    except (OSError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_markdown(report))
    return 1 if args.fail_overdue and (report["counts"]["overdue"] or report["counts"]["invalid_future_date"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
