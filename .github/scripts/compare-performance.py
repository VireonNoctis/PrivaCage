#!/usr/bin/env python3
"""Compare PrivaCage's same-runner benchmark artifacts without inventing thresholds."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"required benchmark report is missing: {path}")
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot compute a percentile with no samples")
    index = max(0, math.ceil(len(ordered) * percent / 100.0) - 1)
    return ordered[min(index, len(ordered) - 1)]


def load_dns(path: Path) -> dict[str, dict[str, Any]]:
    report = load_json(path)
    return {row["benchmark"]: row for row in report["benchmarks"]}


def load_rust(path: Path) -> dict[int, dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            line = line.strip()
            if line:
                item = json.loads(line)
                rows[int(item["dex_size_bytes"])] = item
    if len(rows) != 3:
        raise ValueError(f"expected 3 Rust APK sizes in {path}; found {len(rows)}")
    return rows


def load_startup(path: Path) -> dict[str, float]:
    report = load_json(path)
    runs: list[float] = []
    for benchmark in report.get("benchmarks", []):
        metric = benchmark.get("metrics", {}).get("timeToInitialDisplayMs")
        if not metric:
            continue
        values = metric.get("runs")
        if isinstance(values, list) and values:
            runs.extend(float(value) for value in values)
        elif metric.get("median") is not None:
            runs.append(float(metric["median"]))
    if not runs:
        raise ValueError(f"no timeToInitialDisplayMs metrics found in {path}")
    return {
        "median_ms": statistics.median(runs),
        "p95_ms": percentile(runs, 95),
        "samples": float(len(runs)),
    }


def improvement_percent(baseline: float, candidate: float, higher_is_better: bool) -> float:
    if baseline == 0:
        return 0.0 if candidate == 0 else float("inf")
    delta = candidate - baseline if higher_is_better else baseline - candidate
    return delta / baseline * 100.0


def fmt(value: float, suffix: str = "") -> str:
    return f"{value:,.2f}{suffix}"


def row(name: str, before: str, after: str, improvement: float, note: str = "") -> str:
    label = "faster" if improvement >= 0 else "slower"
    if math.isinf(improvement):
        change = "new/infinite (baseline was zero)"
    else:
        change = f"{abs(improvement):.2f}% {label}"
    extra = f" — {note}" if note else ""
    return f"| {name} | {before} | {after} | {change}{extra} |"


def create_report(results: Path, baseline_sha: str, head_sha: str) -> tuple[str, dict[str, Any]]:
    baseline_dir = results / "baseline"
    head_dir = results / "head"

    dns_before = load_dns(baseline_dir / "dns.json")
    dns_after = load_dns(head_dir / "dns.json")
    rust_before = load_rust(baseline_dir / "rust-apk-scan.jsonl")
    rust_after = load_rust(head_dir / "rust-apk-scan.jsonl")
    startup_before = load_startup(baseline_dir / "startup.json")
    startup_after = load_startup(head_dir / "startup.json")

    metrics: list[dict[str, Any]] = []
    lines = [
        "# PrivaCage performance A/B report",
        "",
        f"- **Baseline commit:** `{baseline_sha}`",
        f"- **Candidate commit:** `{head_sha}`",
        "- Runs are sequential on the same GitHub-hosted runner; results are observations, not CI pass/fail thresholds.",
        "- Android startup runs on an x86_64 CI emulator with emulator detection explicitly suppressed. Android documentation cautions that emulator results are not representative of end-user hardware; use a physical device for absolute startup claims.",
        "- The APK scan workload is a deterministic synthetic ZIP/DEX fixture. It measures whole-file hashing, ZIP/DEX reads, string extraction and indicator matching; it is not a substitute for a scan of a representative signed production APK.",
        "",
        "## Summary",
        "",
        "| Benchmark | Baseline | Candidate | Change |",
        "|---|---:|---:|---:|",
    ]

    startup_gain = improvement_percent(
        startup_before["median_ms"], startup_after["median_ms"], higher_is_better=False
    )
    lines.append(
        row(
            "Cold startup to initial display",
            f"p50 {fmt(startup_before['median_ms'], ' ms')}; p95 {fmt(startup_before['p95_ms'], ' ms')}",
            f"p50 {fmt(startup_after['median_ms'], ' ms')}; p95 {fmt(startup_after['p95_ms'], ' ms')}",
            startup_gain,
            f"{int(startup_after['samples'])} measured startup samples in candidate",
        )
    )
    metrics.append({
        "name": "cold_start_to_initial_display",
        "baseline": startup_before,
        "candidate": startup_after,
        "improvement_percent": startup_gain,
        "higher_is_better": False,
    })

    dns_specs = [
        ("dns_policy_trie_build_10k_rules", "DNS trie build (10,002 rules)", "latency"),
        ("dns_policy_evaluate_10k_rules", "DNS decision throughput (10,002 rules)", "throughput"),
        ("dns_ipv4_udp_blocked_packet_10k_rules", "Blocked IPv4/UDP packet throughput (10,002 rules)", "throughput"),
    ]
    for key, label, kind in dns_specs:
        before = dns_before[key]
        after = dns_after[key]
        before_ns = float(before["median_ns_per_operation"])
        after_ns = float(after["median_ns_per_operation"])
        if kind == "latency":
            gain = improvement_percent(before_ns, after_ns, higher_is_better=False)
            before_text = f"p50 {fmt(before_ns / 1_000_000, ' ms')}; p95 {fmt(float(before['p95_ns_per_operation']) / 1_000_000, ' ms')}"
            after_text = f"p50 {fmt(after_ns / 1_000_000, ' ms')}; p95 {fmt(float(after['p95_ns_per_operation']) / 1_000_000, ' ms')}"
        else:
            before_rate = float(before["operations_per_second"])
            after_rate = float(after["operations_per_second"])
            gain = improvement_percent(before_rate, after_rate, higher_is_better=True)
            before_text = f"{fmt(before_rate, ' op/s')}; p50 {fmt(before_ns / 1_000, ' µs/op')}"
            after_text = f"{fmt(after_rate, ' op/s')}; p50 {fmt(after_ns / 1_000, ' µs/op')}"
        lines.append(row(label, before_text, after_text, gain))
        metrics.append({
            "name": key,
            "baseline": before,
            "candidate": after,
            "improvement_percent": gain,
            "higher_is_better": kind == "throughput",
        })

    for size in sorted(rust_before):
        before = rust_before[size]
        after = rust_after[size]
        before_rate = float(before["throughput_mib_s"])
        after_rate = float(after["throughput_mib_s"])
        gain = improvement_percent(before_rate, after_rate, higher_is_better=True)
        size_mib = size / (1024 * 1024)
        lines.append(
            row(
                f"Rust APK scan ({size_mib:g} MiB DEX fixture)",
                f"{fmt(before_rate, ' MiB/s')}; p50 {fmt(float(before['median_ms']), ' ms')}",
                f"{fmt(after_rate, ' MiB/s')}; p50 {fmt(float(after['median_ms']), ' ms')}",
                gain,
            )
        )
        metrics.append({
            "name": f"rust_apk_scan_{size_mib:g}_mib",
            "baseline": before,
            "candidate": after,
            "improvement_percent": gain,
            "higher_is_better": True,
        })

    lines.extend([
        "",
        "## Interpretation",
        "",
        "Positive percentage changes are improvements for the metric type: lower elapsed time for latency rows and higher throughput for throughput rows. Negative changes are regressions in this run. Differences are not a guarantee of the same magnitude on real devices.",
        "",
        "## Raw report files",
        "",
        "- `baseline/startup.json`, `head/startup.json`: AndroidX Macrobenchmark results.",
        "- `baseline/dns.json`, `head/dns.json`: DNS build/lookup/packet measurements and runner metadata.",
        "- `baseline/rust-apk-scan.jsonl`, `head/rust-apk-scan.jsonl`: synthetic APK scan samples.",
        "",
    ])

    payload = {
        "schema_version": 1,
        "baseline_commit": baseline_sha,
        "candidate_commit": head_sha,
        "startup_emulator_only": True,
        "apk_scan_fixture": "synthetic_stored_dex",
        "metrics": metrics,
    }
    return "\n".join(lines), payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    markdown, payload = create_report(args.results, args.baseline, args.head)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown, encoding="utf-8")
    (args.output.parent / "comparison.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
