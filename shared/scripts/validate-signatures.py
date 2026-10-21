#!/usr/bin/env python3
"""Validate PrivaCage tracker intelligence records using only the stdlib."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FILE = ROOT / "shared" / "tracker-db" / "signatures.json"
VALID_CONFIDENCE = {"low", "medium", "high"}
VALID_STATUS = {"active", "review", "retired"}
VALID_TOP_LEVEL = {"schema_version", "updated_at", "entries"}
VALID_ENTRY = {"id", "name", "category", "indicators", "confidence", "status", "last_verified", "evidence"}
VALID_INDICATORS = {"domains", "sdk_patterns"}
VALID_EVIDENCE = {"url", "description"}
ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ValidationFailure(Exception):
    """Raised when a database cannot be safely accepted."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def validate_date(value: object, field: str) -> None:
    require(isinstance(value, str), f"{field} must be a YYYY-MM-DD string")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValidationFailure(f"{field} is not a valid calendar date: {value!r}") from exc
    require(parsed.isoformat() == value, f"{field} must use canonical YYYY-MM-DD format")


def validate_domain(value: object, context: str) -> None:
    require(isinstance(value, str) and value == value.lower(), f"{context} must be lowercase text")
    require(bool(value) and len(value) <= 253, f"{context} must be 1-253 characters")
    require(not value.endswith("."), f"{context} must not end with a dot")
    labels = value.split(".")
    require(len(labels) >= 2, f"{context} must be a fully qualified domain")
    require(all(DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels),
            f"{context} is not a valid hostname: {value!r}")


def validate_https_url(value: object, context: str) -> None:
    require(isinstance(value, str) and bool(value), f"{context} must be a non-empty URL")
    parsed = urlparse(value)
    require(parsed.scheme == "https", f"{context} must use HTTPS")
    require(bool(parsed.hostname), f"{context} must include a hostname")
    require(parsed.username is None and parsed.password is None,
            f"{context} must not contain credentials")


def validate_database(document: object) -> list[str]:
    """Return validation errors; return an empty list when valid."""
    try:
        require(isinstance(document, dict), "document must be a JSON object")
        require(set(document) == VALID_TOP_LEVEL,
                "top-level fields must be exactly schema_version, updated_at, entries")
        require(type(document["schema_version"]) is int, "schema_version must be an integer")
        require(document["schema_version"] == 1, "unsupported schema_version; expected 1")
        validate_date(document["updated_at"], "updated_at")
        require(isinstance(document["entries"], list), "entries must be an array")

        seen_ids: set[str] = set()
        for index, entry in enumerate(document["entries"]):
            context = f"entries[{index}]"
            require(isinstance(entry, dict), f"{context} must be an object")
            require(set(entry) == VALID_ENTRY,
                    f"{context} fields must be exactly: {', '.join(sorted(VALID_ENTRY))}")

            entry_id = entry["id"]
            require(isinstance(entry_id, str) and ID_PATTERN.fullmatch(entry_id) is not None,
                    f"{context}.id must be lowercase kebab-case")
            require(entry_id not in seen_ids, f"duplicate id: {entry_id}")
            seen_ids.add(entry_id)

            for field in ("name", "category"):
                value = entry[field]
                require(isinstance(value, str) and bool(value) and value.strip() == value,
                        f"{context}.{field} must be non-empty trimmed text")

            require(isinstance(entry["confidence"], str) and entry["confidence"] in VALID_CONFIDENCE,
                    f"{context}.confidence must be one of {sorted(VALID_CONFIDENCE)}")
            require(isinstance(entry["status"], str) and entry["status"] in VALID_STATUS,
                    f"{context}.status must be one of {sorted(VALID_STATUS)}")
            validate_date(entry["last_verified"], f"{context}.last_verified")

            indicators = entry["indicators"]
            require(isinstance(indicators, dict), f"{context}.indicators must be an object")
            require(set(indicators).issubset(VALID_INDICATORS),
                    f"{context}.indicators has unsupported fields")
            require(bool(indicators), f"{context}.indicators must not be empty")
            for key, values in indicators.items():
                require(isinstance(values, list) and bool(values),
                        f"{context}.indicators.{key} must be a non-empty array")
                require(all(isinstance(item, str) and bool(item) and item.strip() == item
                            for item in values),
                        f"{context}.indicators.{key} values must be non-empty trimmed strings")
                require(len(values) == len(set(values)),
                        f"{context}.indicators.{key} contains duplicates")
                if key == "domains":
                    for domain_index, domain in enumerate(values):
                        validate_domain(domain, f"{context}.indicators.domains[{domain_index}]")

            evidence = entry["evidence"]
            require(isinstance(evidence, list) and bool(evidence),
                    f"{context}.evidence must be a non-empty array")
            seen_urls: set[str] = set()
            for evidence_index, source in enumerate(evidence):
                source_context = f"{context}.evidence[{evidence_index}]"
                require(isinstance(source, dict), f"{source_context} must be an object")
                require(set(source) == VALID_EVIDENCE,
                        f"{source_context} fields must be exactly url and description")
                validate_https_url(source["url"], f"{source_context}.url")
                require(source["url"] not in seen_urls, f"{source_context}.url is duplicated")
                seen_urls.add(source["url"])
                description = source["description"]
                require(isinstance(description, str) and bool(description)
                        and description.strip() == description,
                        f"{source_context}.description must be non-empty trimmed text")
    except (ValidationFailure, KeyError, TypeError, ValueError) as exc:
        return [str(exc)]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE,
                        help="path to tracker database JSON")
    args = parser.parse_args(argv)

    try:
        with args.file.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as exc:
        print(f"ERROR: cannot read {args.file}: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON in {args.file}: {exc}", file=sys.stderr)
        return 2

    errors = validate_database(document)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"OK: {args.file} passed schema validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
