# Next 1,000 engineering milestones (121–1120)

**Purpose:** continue the existing milestones 1–120 with a 1,000-item, numbered engineering acceptance register. This is a backlog, not a completion claim. Every milestone must be implemented, reviewed and verified separately.

## Execution rules

- **Milestone 121** is the concrete Go tracker-input hardening change in the accompanying pull request: duplicate-key rejection (including escaped-equivalent keys), an 8 MiB input ceiling, and a 128-level JSON nesting limit. Its status remains **CI pending** until the relevant workflow passes on the PR head.
- All other milestones begin as **Planned**. A title or acceptance criterion is not evidence that the work exists.
- Split execution into small pull requests grouped by module. A milestone may be marked verified only after its tests pass on the exact commit being considered.
- Keep device routing, Android Keystore invalidation, Windows policy behavior, iOS entitlement work, and legal copy behind their real external validation gates. Do not replace them with mocks while claiming full coverage.
- Prefer regression tests for bugs: preserve a minimal failing fixture, fix the root cause, and prove the previous behavior is no longer possible.
- No private keys, real personal records, unlicensed APKs, or live user DNS history belong in fixtures or CI artifacts.

## Phase register

| Phase | Milestones | Scope |
|---|---:|---|
| [01 — Shared input integrity, Android DNS and VPN](phase-01-foundation-dns-vpn.md) | 121–220 | Parser limits, DNS packet correctness, lifecycle, rollback and local-history resilience |
| [02 — APK inspection and metadata cleanup](phase-02-apk-metadata.md) | 221–320 | Hostile ZIP/DEX/manifest inputs, signing evidence, metadata preservation and atomic output |
| [03 — Tracker intelligence and alternative-app catalogue](phase-03-tracker-catalogues.md) | 321–420 | Evidence provenance, freshness, lifecycle rules, false positives and safe destination handling |
| [04 — Encrypted profiles, signatures and audit checkpoints](phase-04-crypto-audit.md) | 421–520 | Strict schemas, cryptographic failure paths, signature scope, cross-language parity and recovery |
| [05 — E2EE sync, device trust and relay integrity](phase-05-sync-relay.md) | 521–620 | Identity binding, replay protection, roster revisions, revocation, retention and durable writes |
| [06 — Windows privacy audit and reversible hardening](phase-06-windows-hardening.md) | 621–720 | Policy capability detection, safe mutation, protected backups, restore correctness and truthful reporting |
| [07 — Web console, API and dashboard boundaries](phase-07-web-backend.md) | 721–820 | Schema validation, safe rendering, origin control, truthful data states and responsive frontend quality |
| [08 — Privacy-rights drafts and legal workflows](phase-08-rights-workflows.md) | 821–920 | Source-backed templates, deadlines, user consent, safe contact handling and local record lifecycle |
| [09 — CI, test automation, reproducible builds and performance](phase-09-ci-release-validation.md) | 921–1020 | Trigger coverage, test execution, secrets hygiene, build provenance and performance/fuzz reliability |
| [10 — Accessibility, UX, documentation, privacy governance and release gates](phase-10-ux-accessibility-governance.md) | 1021–1120 | Accessible monochrome UI, data controls, accurate copy, docs parity, incident process and release gates |

## Status semantics

- **Planned:** no implementation is claimed.
- **Implemented, verification pending:** code and targeted tests exist, but the required CI/platform checks have not yet passed on the current head.
- **Verified:** tests or platform evidence passed on the exact commit, with the check/result recorded.
- **Blocked externally:** the required emulator/device, OS edition, entitlement, legal review, or operator-controlled service is not available. Record the blocker precisely and do not substitute a fake result.

The individual phase files contain 100 acceptance targets each. They intentionally emphasize regression prevention, fail-closed behavior, bounded inputs, atomic changes, privacy-safe diagnostics, and truthful claims about platform limits.
