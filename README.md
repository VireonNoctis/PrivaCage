# PrivaCage

**Understand what your device exposes. Block what you can. Know what you cannot.**

PrivaCage is an open-source, local-first privacy auditing project for Android, iOS, and Windows. Its goal is to help people understand app permissions, identify known tracking components, inspect observable network activity, apply enforceable privacy rules, and keep an evidence-backed local audit trail.

PrivaCage is not an anonymity product and does not claim that an ordinary app can observe or disable every operating-system or manufacturer activity. Platform boundaries are part of the product, not fine print.

## Project status

The repository contains the evidence-first tracker intelligence foundation and an isolated, tested-by-design Kotlin/JVM DNS policy component. It is not yet a functioning mobile app or device-wide network blocker.

| Area | Status | Honest scope |
|---|---|---|
| Tracker intelligence format | Initial implementation | Evidence-backed records and a validator; no tracker entries ship until verified |
| Android DNS policy core | Initial implementation | Parses supported DNS queries, validates EDNS(0), and returns allow/block/malformed decisions |
| Android IPv4 UDP DNS packet pipeline | Initial implementation | Evaluates DNS policy, builds valid REFUSED reply packets for blocked domains, and returns allowed queries for forwarding; not connected to a VPN service |
| Android local network filtering | Not implemented | Requires a real VpnService, upstream forwarding, UDP/TCP handling, lifecycle integration, and device/emulator tests |
| APK static analysis | Planned | Findings indicate capability or signatures, not proof of execution |
| Android permission auditing | Planned | Ordinary apps cannot freely revoke other apps' permissions |
| iOS companion | Planned, restricted | Must respect sandbox and NetworkExtension entitlement limits |
| Windows network controls | Planned | Explicit firewall rules require appropriate privileges |
| Legal request assistant | Planned | Drafts and tracks requests; cannot verify deletion from company systems |

## Principles

- Local-first: core auditing should work without an account or required cloud service.
- No product telemetry by default.
- Evidence over fear: distinguish observed facts, static indicators, inferences, and unknowns.
- Enforcement must be real: controls must apply an OS-level action and report its outcome.
- Least privilege: elevated access needs a clear purpose and explicit explanation.
- Reproducible and testable: data formats and security-sensitive rules require validation.
- No paid placement in recommendations or tracker intelligence.

## First milestone

1. Define a versioned tracker format with source provenance and review dates.
2. Validate records before they enter the shared database.
3. Run validation and tests in continuous integration.
4. Require evidence in contributions; do not populate the database with guesses.
5. Use the database later in APK analysis and network filtering without treating a signature match as proof of exfiltration.

## Repository map

- `docs/architecture.md` — system boundaries and data flow.
- `docs/threat-model.md` — assets, threats, and non-goals.
- `docs/privacy-opportunity-backlog.md` — candidate features grounded in real capabilities.
- `docs/research-notes/privacy-concerns.md` — sourced privacy concerns and platform constraints.
- `CONTRIBUTING.md` — evidence and review requirements.
- `android-core/` — isolated Kotlin/JVM DNS policy evaluator, IPv4 UDP DNS packet codec, packet processor, tests, and Gradle configuration.
- `shared/tracker-db/schema.md` — tracker database contract.
- `shared/tracker-db/signatures.json` — currently empty, valid database.
- `shared/scripts/validate-signatures.py` — standard-library validator.
- `tests/test_validate_signatures.py` — regression tests.

## Run checks locally

Requires Python 3.11 or newer. The tracker validator and tests use only the Python standard library.

    python shared/scripts/validate-signatures.py
    python -m unittest discover -s tests -v

The Android DNS core separately requires JDK 17 and Gradle:

    cd android-core
    gradle test

An empty tracker database is valid. It is safer to ship zero verified entries than to pretend an invented or weakly sourced list is reliable.

## Platform reality

- Android: a user-approved VpnService can route traffic through a local tunnel and enforce supported network rules. It does not grant visibility into arbitrary app internals, HTTPS payloads, every system service, or all OEM/baseband traffic. Only one ordinary VPN service can be active at a time.
- iOS: sandboxing prevents one ordinary app from inspecting another app's executable or intercepting its system calls. Network filtering depends on supported NetworkExtension APIs, entitlements, distribution model, and OS policy.
- Windows: firewall rules can block specified traffic when the user has the required privileges. A firewall-rule manager is not unrestricted packet inspection or complete attribution of every system connection.
- IP addresses: a remote endpoint ordinarily sees the public source IP of the network path reaching it. A VPN or proxy changes which intermediary sees that address; it shifts trust rather than making a connection inherently anonymous.
- Static analysis: a permission, SDK, or domain string in an APK is evidence of declared capability or a possible indicator, not proof that the app used it or transmitted personal data.
- Legal requests: a sent request is not proof of deletion.

## Security reporting

Please do not publish details of an unpatched vulnerability involving user data or security controls. Use GitHub's private vulnerability reporting feature if it is available for this repository.

## License

MIT. See LICENSE.
