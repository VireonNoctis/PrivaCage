use pcage_tracker_intelligence::{
    advanced::scan_apk, Catalog, Entry, Evidence, Indicators,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{self, File},
    io::Write,
    path::PathBuf,
    time::Instant,
};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

const SAMPLE_COUNT: usize = 5;
const STRING_STRIDE: usize = 1024;

fn synthetic_catalog() -> Catalog {
    let entries = (0..24)
        .map(|index| Entry {
            id: format!("benchmark-sdk-{index}"),
            name: format!("Synthetic SDK {index}"),
            category: "benchmark".into(),
            indicators: Indicators {
                sdk_patterns: vec!["com.example.analytics.**".into()],
                dex_strings: vec![
                    if index % 2 == 0 {
                        "com.example.analytics.TrackerClient".into()
                    } else {
                        "com.example.telemetry.Dispatcher".into()
                    },
                ],
                ..Indicators::default()
            },
            confidence: "high".into(),
            status: "active".into(),
            last_verified: Some("2026-10-25".into()),
            evidence: vec![Evidence {
                id: None,
                url: "https://example.org/synthetic-benchmark".into(),
                description: "Synthetic evidence used only for the performance harness".into(),
                retrieved_at: None,
                source_type: Some("benchmark_fixture".into()),
            }],
            entity_ids: Vec::new(),
            sdk_ids: Vec::new(),
            localized_names: BTreeMap::new(),
        })
        .collect();

    Catalog {
        schema_version: 1,
        updated_at: "2026-10-25".into(),
        entries,
    }
}

fn write_synthetic_apk(dex_size: usize) -> Result<PathBuf, Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!(
        "privacage-performance-{}-{dex_size}.apk",
        std::process::id()
    ));
    let file = File::create(&path)?;
    let mut archive = ZipWriter::new(file);
    let options =
        SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    // Deliberately synthetic manifest: the benchmark is focused on APK hashing,
    // ZIP/DEX reading, string extraction, and indicator matching—not manifest fidelity.
    archive.start_file("AndroidManifest.xml", options)?;
    archive.write_all(b"<manifest package=\"org.privacage.synthetic\"/>")?;

    let mut dex = vec![0u8; dex_size];
    let tracker = b"com.example.analytics.TrackerClient";
    let telemetry = b"com.example.telemetry.Dispatcher";
    for offset in (0..dex.len()).step_by(STRING_STRIDE) {
        let value = if (offset / STRING_STRIDE) % 2 == 0 {
            tracker.as_slice()
        } else {
            telemetry.as_slice()
        };
        let end = (offset + value.len()).min(dex.len());
        dex[offset..end].copy_from_slice(&value[..end - offset]);
    }

    archive.start_file("classes.dex", options)?;
    archive.write_all(&dex)?;
    archive.finish()?;
    Ok(path)
}

fn percentile(sorted: &[u128], percentile: usize) -> u128 {
    let index = sorted.len().saturating_mul(percentile).div_ceil(100).saturating_sub(1);
    sorted[index.min(sorted.len() - 1)]
}

fn bench_size(dex_size: usize, catalog: &Catalog) -> Result<(), Box<dyn Error>> {
    let path = write_synthetic_apk(dex_size)?;
    let apk_size = fs::metadata(&path)?.len();
    let mut sink = 0usize;

    // One unreported warmup prevents the first measured iteration from paying
    // one-time filesystem/runtime initialization costs.
    let (observations, reports) = scan_apk(&path, catalog)?;
    sink = sink.wrapping_add(observations.len()).wrapping_add(reports.len());

    let mut elapsed_ns = Vec::with_capacity(SAMPLE_COUNT);
    let mut printable_strings = 0usize;
    for _ in 0..SAMPLE_COUNT {
        let start = Instant::now();
        let (observations, reports) = scan_apk(&path, catalog)?;
        let elapsed = start.elapsed().as_nanos().max(1);
        printable_strings = reports
            .iter()
            .find(|report| report.get("dex_file").is_some())
            .and_then(|report| report.get("printable_strings"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as usize;
        sink = sink
            .wrapping_add(observations.len())
            .wrapping_add(reports.len());
        elapsed_ns.push(elapsed);
    }

    elapsed_ns.sort_unstable();
    let median_ns = elapsed_ns[elapsed_ns.len() / 2];
    let p95_ns = percentile(&elapsed_ns, 95);
    let apk_mib = apk_size as f64 / (1024.0 * 1024.0);
    let median_seconds = median_ns as f64 / 1_000_000_000.0;

    println!(
        "PERF_JSON:{}",
        json!({
            "benchmark": "rust_apk_scan",
            "fixture": "synthetic_stored_dex",
            "dex_size_bytes": dex_size,
            "apk_size_bytes": apk_size,
            "catalog_entries": catalog.entries.len(),
            "samples": SAMPLE_COUNT,
            "median_ms": median_ns as f64 / 1_000_000.0,
            "p95_ms": p95_ns as f64 / 1_000_000.0,
            "throughput_mib_s": apk_mib / median_seconds,
            "printable_strings": printable_strings,
            "result_sink": sink
        })
    );

    fs::remove_file(path)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let catalog = synthetic_catalog();
    for size_mib in [8usize, 32, 64] {
        bench_size(size_mib * 1024 * 1024, &catalog)?;
    }
    Ok(())
}
