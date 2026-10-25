# 05 — APK Analysis, Tracker Signatures and Privacy Labels

**Research status:** current-method review, 25 October 2026  
**Decision this note supports:** create useful pre-install evidence without overstating static analysis.

## 1. A privacy label is an evidence summary, not a moral score

Static analysis can identify declared permissions, components, package metadata, embedded SDK patterns and strings that look like endpoints. Exodus Privacy describes this general family of Android analysis: it detects known embedded tracker signatures and requested permissions; its FAQ explicitly warns that a found signature is not proof the tracker is active and that the list is not complete ([S17](SOURCES.md#s17), [S18](SOURCES.md#s18)). PrivaCage should inherit that epistemic discipline.

The label should answer four separate questions:

1. **Capability:** what permissions/components does the APK declare or request?
2. **Dependency evidence:** which known SDK signatures were found, in which APK version/hash, using which database version?
3. **Endpoint evidence:** which hostnames/IP-like strings were found in the APK, and from which scan mechanism? A hard-coded string is not proof of a live connection.
4. **Runtime observations:** what has PrivaCage actually observed on this device while the app ran, with what attribution confidence? This field must be empty unless a real telemetry source exists.

Do not mix these into one unqualified list of “trackers that collected your data.”

## 2. APK intake and reproducibility

The strongest MVP scan path is a user-selected APK file. Before scanning, compute a cryptographic hash (SHA-256), record file size, APK package name/version where successfully parsed, signer certificate fingerprints, scan tool version and tracker database version. The scan should be local by default. Users should be told that APK analysis is not a guarantee of safety and that malware or obfuscated/dynamic code can evade signatures.

For package inventory scan, respect Android package visibility and store policy; do not assume every installed package can be discovered on every build ([S05](SOURCES.md#s05)). Do not download APKs from unofficial locations without a separate integrity and legal review. Do not store APK copies after scanning unless the user opts in to retain them.

## 3. Static analysis pipeline

Minimum pipeline:

1. Verify that the input is a valid APK/ZIP structure and protect against decompression bombs and path traversal.
2. Parse `AndroidManifest.xml` and classify permissions by platform API level and protection type.
3. Parse package name/version, min/target SDK, signing certificate details and declared exported components.
4. Scan DEX and native-library contents using versioned signatures for known analytics/ad/attribution/crash/engagement SDKs.
5. Collect candidate hostname strings only with their source artifact/offset; classify candidates as `embedded_string`, `manifest_metadata`, or another explicit evidence source.
6. Compare signature results and known false-positive exceptions; generate a label with caveats and a machine-readable output.
7. Test parser error handling against malformed and oversized inputs; unsupported APKs should fail clearly, not produce a green “clean” label.

## 4. Signature database quality

Each tracker entry should include:

- stable identifier and display name;
- organization/project attribution where supported by evidence;
- SDK/package/class/domain patterns with exact semantics;
- evidence links from vendor documentation, official packages, public source or reproducible samples;
- first and last reviewed date, maintainer and database version;
- confidence and limitation note;
- test APK/sample fixture hashes where licensing permits;
- change history and removal/reclassification rationale.

A domain-only match is weaker than a distinctive SDK class signature, and a generic class name is weaker than a combined pattern. Signature versioning matters: if a database update changes a result, the report needs to reveal which version generated it. Expired or unreviewed entries should be marked stale, not silently treated as current fact.

## 5. False positives and false negatives

**False positive examples:** a library is embedded but dead-code-stripped/disabled; a common networking component resembles a signature; a domain belongs to a shared CDN; a string is documentation or a test endpoint.

**False negative examples:** new SDK version changes package names; obfuscation changes class patterns; the SDK is downloaded later; reflection/dynamic loading hides classes; native code is not analyzed; endpoint strings are constructed at runtime; tracker behavior is server-configured.

Use confidence categories tied to evidence, not to an invented numerical percentage. A displayed score like 0.97 requires a calibrated dataset and a reproducible evaluation; do not assign probability scores by intuition.

## 6. Privacy label schema

Suggested top-level structure:

```json
{
  "schema_version": 1,
  "scan": {
    "apk_sha256": "<actual sha256>",
    "scanner_version": "<version>",
    "tracker_db_version": "<version>",
    "scanned_at": "<timestamp>",
    "scan_scope": ["manifest", "dex_signatures", "embedded_strings"]
  },
  "capabilities": [],
  "sdk_indicators": [],
  "endpoint_candidates": [],
  "runtime_observations": [],
  "limitations": []
}
```

The example deliberately uses placeholders. An unrun scan must not return placeholder data as if it were real.

Every finding should include `evidence_kind`, `evidence_ref` (artifact/offset or source link), `confidence_label`, `explanation`, `false_positive_notes` and `last_reviewed`. Runtime observations belong to a different source/trust category than static findings.

## 7. Privacy label copy

Prefer:

- “Requests location permission; this does not prove location was read.”
- “Known analytics SDK signature detected in the scanned APK. Presence does not prove execution or transmission.”
- “Potential hostname string found in the APK; no runtime connection is implied.”
- “PrivaCage observed a DNS query for this hostname at this time; payload contents were not inspected.”
- “No matching signature was found in this scan. This is not a guarantee that the APK contains no tracker.”

Avoid “clean,” “spyware,” “sells your data,” “reads contacts every day” or “100% private” unless evidence and scope truly support that exact assertion.

## 8. Comparison with developer disclosures

Apple's App Privacy Details are developer-provided disclosures about collected data, linking and purposes, including partner SDKs. Apple states that the developer is responsible for accurate, current answers ([S14](SOURCES.md#s14)). Google Play's Data safety section similarly provides a developer-facing disclosure process; treat platform-store disclosures as one input rather than independent runtime measurement. A useful report places disclosure next to static evidence and runtime evidence, highlighting differences without declaring deception solely from a mismatch.

## 9. Acceptance criteria

- Every result can be reproduced from the same APK hash, scanner version and DB version.
- No signature match is described as confirmed data transmission.
- Malformed, truncated, encrypted, unsupported or overly large inputs receive explicit non-success states.
- Static evidence, developer declarations and runtime observations never share a field that loses provenance.
- Database contributions include sources, tests, review dates and a path to challenge a result.