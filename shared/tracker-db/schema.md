# Tracker database schema — version 1

A match means a known indicator was found. It does not by itself prove runtime execution, data collection, exfiltration, or malicious intent.

## Top-level document

The JSON document has exactly three fields: schema_version (integer 1), updated_at (ISO date YYYY-MM-DD), and entries (array). An empty entries array is valid.

## Entry fields

| Field | Type | Requirement |
|---|---|---|
| id | string | Unique stable lowercase kebab-case identifier |
| name | string | Non-empty human-readable component/service name |
| category | string | Category such as analytics, advertising, fingerprinting, crash_reporting, or other |
| indicators | object | At least one non-empty domains or sdk_patterns array |
| indicators.domains | string array | Lowercase hostnames, no URL scheme, path, or port; matches must use exact-host or DNS-label-boundary semantics |
| indicators.sdk_patterns | string array | Dotted Java/Kotlin package or class indicators, optionally ending in `.*` (direct package members) or `.**` (package subtree); static strings are not proof of runtime use |
| confidence | string | low, medium, or high |
| status | string | active, review, or retired |
| last_verified | string | Real calendar date in ISO YYYY-MM-DD format |
| evidence | array | At least one source object |
| evidence[].url | string | HTTPS URL |
| evidence[].description | string | What the source supports |

Unknown fields are rejected in version 1 so typos cannot silently become ignored policy. Schema extensions must update the version, validator, and tests together.

## Quality rules

- IDs remain stable across revisions.
- Domain indicators are normalized to lowercase and validated as hostnames.
- The validator checks URL structure, not whether a source is trustworthy or online.
- High confidence requires human evidence review; the validator cannot assign truth.
- Retired entries remain available for historical context but must not drive active blocking.
- Review-status entries must be shown as uncertain and must not silently become hard blocks.

## Matching and interpretation contract

- A domain record identifies a service endpoint, not an SDK installed in a particular app. DNS matches can be caused by browser pages, embedded web content, system components, shared libraries, or unrelated uses of a shared host.
- Domain matching must use exact-host or DNS-label-boundary suffix semantics. A host such as sub.metrics.example may match metrics.example, but notmetrics.example must not. Never use arbitrary substring matching for hostnames.
- SDK/package patterns are static indicators. Obfuscation, native code, dynamic loading, custom builds, and first-party proxies can produce false negatives; strings can be unused or bundled without execution.
- active means an indicator may be offered for explicit user-reviewed rules, not that it is malicious or safe to block globally. review must be excluded from bulk active-domain import. retired is historical and must not drive enforcement.
- Evidence dates record a human review of the cited source, not automated proof that the endpoint is live. CI freshness checks force re-review but do not validate the source itself.
- Keep broad shared infrastructure review-only when collateral breakage or service ambiguity is high. Never elevate a record based only on vendor reputation or category.
