# Architecture

## Design goal

Build a local-first privacy auditor with a shared evidence format and platform-native enforcement. Shared code may normalize records and validate data; it must not erase important differences between Android, iOS, and Windows.

## Proposed layers

1. Platform adapters collect facts exposed by supported OS APIs.
2. An evidence normalizer converts facts into typed events while retaining provenance and confidence.
3. A policy engine evaluates explicit user rules against observable attributes.
4. Enforcement adapters apply rules through supported platform controls and return a result, including failure.
5. A local event store records decisions and evidence with retention controls.
6. The UI explains results without converting guesses into facts.
7. Shared intelligence provides versioned tracker/SDK indicators with evidence URLs and review dates.

If a platform does not expose an event, show that monitoring is unavailable or limited rather than fabricating an event.

## Event model direction

Events should distinguish observed facts, static indicators, inferences, enforcement results, and unknowns. Every event should include a timestamp, platform/source, event type, relevant app identity where the OS supplies it, decision/result where applicable, and evidence provenance. Do not store packet payloads by default.

## Android first slice

The current Kotlin/JVM components are preparatory only: a DNS policy evaluator, an IPv4 UDP packet codec, and a processor connecting them. The processor can return an actual REFUSED reply packet for a blocked domain, explicitly mark an allowed query as requiring forwarding, and drop malformed DNS. It does not open a TUN interface, forward allowed requests, or write replies to a device.

Before calling the Android feature functional, it must establish a user-approved VpnService TUN interface and real packet loop; enforce user-selected domain rules; forward allowed queries to a configured resolver; support UDP and TCP DNS, define IPv6 behavior, preserve packet IDs, ports, checksums, and response routing; handle cancellation, VPN revocation, network changes, captive portals, and failure recovery; and test on emulator/device. Encrypted DNS protocols and direct-to-IP connections remain outside ordinary DNS filtering.

Do not add permission interception, fake-data injection, or arbitrary sensor monitoring until a supported API or explicitly gated rooted extension actually implements it.

## iOS

Use public Apple APIs and approved entitlements only. NetworkExtension design depends on entitlement approval and distribution route. The companion can explain available privacy reports and native settings but cannot inspect other apps' binaries or override their permissions.

## Windows

Start with read-only inventory of supported firewall state, then add explicit, user-confirmed rules with administrator privileges when needed. Record the exact rule added and verify it after applying. Do not claim unrestricted process attribution from standard firewall APIs alone.

## Data flow

OS evidence → typed event → policy evaluation → OS action when supported → verified result → local audit log.

For static scanning: user-selected APK → manifest/DEX inspection → signature matches and evidence → privacy label with uncertainty.

The tracker database is advisory intelligence. It does not replace platform enforcement and is not proof of runtime behavior.

## Privacy properties

- No required account or backend for core functionality.
- No outbound analytics or crash-reporting SDK by default.
- Network access by PrivaCage itself must be documented and limited to explicitly requested updates or user-initiated actions.
- Rules and logs remain local unless exported by the user.
- Automatic rule updates require authenticated metadata, integrity checks, and a rollback policy.
