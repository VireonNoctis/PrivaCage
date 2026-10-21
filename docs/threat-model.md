# Initial Threat Model

This is a working threat model, not a security audit. Update it as executable components are added.

## Assets

- User network metadata and app-usage patterns.
- Local audit logs, rule choices, and exported reports.
- APKs selected for scanning and metadata extracted from them.
- Legal-request drafts and personal identifiers entered by the user.
- Integrity of tracker signatures and update packages.
- Trust in the accuracy of product warnings.

## Threats

- A signature falsely labels a benign service or misses a new tracker.
- Malformed APKs or packets exploit a parser.
- An attacker poisons tracker data or update packages.
- Logs reveal sensitive habits on a shared, backed-up, or compromised device.
- A user assumes a blocked DNS name means all telemetry is blocked.
- A control reports success when the OS denied it.
- A malicious PrivaCage update collects data.
- Recommendations are manipulated by commercial incentives.
- A legal workflow implies that a company deleted data when it has not.

## Mitigations

- Evidence URLs, verification dates, stable IDs, review status, and human review.
- Strict input validation, bounded parsing, fuzz tests for packet/APK parsers, and dependency minimization.
- Signed releases and authenticated update metadata before automatic updates.
- Local-only storage by default, limited event fields, retention controls, and explicit export.
- Separate observed facts from static indicators and inferences.
- Verify enforcement outcomes through the OS and surface failures.
- Require evidence for app recommendations and prohibit paid placement.
- Track request-submission evidence separately from company responses and confirmed deletion.

## Non-goals and limits

- Protection against a fully compromised OS, kernel, baseband, or malicious firmware.
- Blocking every manufacturer or carrier telemetry path on stock devices.
- Seeing arbitrary HTTPS contents without an explicitly configured interception mechanism.
- Preventing an app from sending data over an allowed connection when that data is not visible to the filter.
- Guaranteeing anonymity, eliminating all fingerprinting, or preventing all network correlation.
- Verifying deletion from a third party's systems without reliable evidence from that party or an independent audit.

## Safety considerations

Stalkerware signals must be framed carefully: a hidden icon, unusual accessibility permission, or persistence behavior is a review signal, not conclusive proof of abuse. Safety guidance must be cautious because removing software or changing settings can alert an abuser or put a user at greater risk.
