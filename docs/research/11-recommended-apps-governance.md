# 11 — Recommended Apps Directory: Evidence and Governance

**Research status:** governance design, 25 October 2026  
**Decision this note supports:** make recommendations useful without turning a community directory into an unverified trust badge.

## 1. Why recommendations are a security surface

A privacy tool's app directory influences users' installs, accounts and data migrations. A stale recommendation can become unsafe after an acquisition, policy change, dependency update or security incident. A product name, open-source repository or privacy policy alone does not prove good privacy behavior. Conversely, one analytics dependency is not automatically proof that an app is unfit: purpose, data flow and user trade-offs matter.

The recommendation list should be evidence-led and non-commercial. No paid placement, affiliate ranking or sponsor preference. Category ordering should be neutral (alphabetical or clear user-selected filters) and every entry should show its evidence date and confidence.

## 2. Minimum entry record

- Display name and platform(s), official developer identity and official download link(s).
- Category and one-line purpose.
- Source repository or independent audit where available.
- Official privacy policy and privacy/security documentation.
- Jurisdiction and company/controller information if documented.
- Tracker/SDK scan source and version, scan date, APK/app version and limitations.
- Known trade-offs: account required, cloud dependency, metadata exposure, limited E2E scope, telemetry, closed-source components or platform restrictions.
- Evidence quality label: `independently_audited`, `source_reviewed`, `static_scan_only`, `developer_claim_only`, `insufficient_evidence`.
- Review status and next review date, including any active concern.

Never convert absence of evidence into “no trackers” or “safe.”

## 3. Review process

1. Contributor supplies a concrete evidence set and sources.
2. Automated format/schema validation checks required fields, allowed URL schemes, duplicates, version/date formats and source presence.
3. The same static scanning pipeline can collect SDK/permission indicators where binaries are lawfully available and supported. Static scan findings remain indicators.
4. A maintainer reviews source quality, trade-offs and phrasing.
5. A second reviewer signs off new entries or major trust-status changes.
6. The changelog records all changes and the evidence behind them.
7. Entries receive a defined review cadence. Changes in policy, ownership, severe incidents or newly observed SDKs can trigger an earlier review.
8. A delist/review path lets maintainers suspend a recommendation quickly while evidence is checked.

The specific “two maintainer approvals” rule from the initial idea is a policy choice, not a technical fact. If the project has only one maintainer, label entries “provisional” rather than pretending a second reviewer exists.

## 4. Status labels

Use labels users can interpret:

- **Reviewed:** cited evidence was reviewed on a date; scope is clear.
- **Provisional:** a useful candidate with gaps requiring follow-up.
- **Under review:** new evidence conflicts with the prior recommendation.
- **Withdrawn:** no longer recommended, with the reason and date recorded.

Avoid “certified private,” “guaranteed safe,” or “zero tracking” unless an independently defined certification scheme actually exists and the evidence supports the exact scope.

## 5. Database design

Keep the directory in versioned structured data with a schema validator and generated human-readable changelog. Use JSON Schema or equivalent validation and reject untrusted HTML/URL injection. Download links should use official publisher sources or recognized app stores; don't link to arbitrary APK mirrors merely to offer convenience.

The signature scanner should not automatically relabel every recommendation based on a single signature. Instead it opens a review item containing the new evidence. This prevents a noisy signature update from silently changing public trust status.

## 6. Maintenance and retirement

- Check links and version evidence on the review schedule.
- If a source becomes unavailable, mark the record stale rather than assume it remains correct.
- Re-scan only where a current package can be lawfully obtained and the result is reproducible.
- Store previous versions and reasoned diffs.
- Allow users to report problems with evidence; distinguish a report from a confirmed issue.
- Do not automatically remove an app based on an unverified allegation, but provide a rapid temporary “under review” state when the concern is serious.

## 7. Acceptance criteria

- Every entry has source links, review date, trade-offs and a review state.
- No entry enters “Reviewed” status without a traceable evidence record.
- Static tracker findings are described as SDK indicators, not proof of behavior.
- A single-maintainer project does not fake multiple independent approvals.
- Changes to the directory are versioned and have a human-readable rationale.