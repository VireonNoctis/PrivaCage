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
| indicators.domains | string array | Lowercase hostnames, no URL scheme, path, or port |
| indicators.sdk_patterns | string array | Concrete package/class patterns explained in the contribution |
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
