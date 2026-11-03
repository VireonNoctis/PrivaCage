# Strict No-Telemetry Policy

**Version:** 0.1-draft  
**Prepared:** 3 November 2026  
**Applies to:** all PrivaCage-controlled client code. The Android client has a CI-enforced source/dependency scan; the web workspace remains subject to the same prohibition but its dependency graph is not yet covered by that Android-specific scanner.

## 1. Rule

PrivaCage must not collect or transmit product telemetry. The project does not build a behavioural profile of app users and does not receive a silent stream of usage events from the Android client.

The following are prohibited unless the product owner changes this policy, documents the exact necessity and data flow, obtains legal review, and explicitly updates the user-facing notice before implementation:

- product analytics, usage analytics or event tracking;
- advertising identifiers, ad attribution, retargeting or cross-app tracking;
- session replay, heatmaps, screen recording or interaction fingerprinting;
- remote crash reporting, ANR upload, stack-trace upload or automatic diagnostic dumps;
- automatic device/app inventory uploads;
- automatic DNS-history, domain, permission-audit, APK-report or rights-tracker uploads;
- automatic AI requests or background document submissions;
- silent remote configuration that changes privacy behaviour;
- hidden background requests to project-operated collection endpoints; and
- collection of account identity, contacts, precise location, microphone/camera content or advertising IDs for analytics or product measurement.

No analytics, advertising, session-replay or remote crash-reporting SDK may be added to the Android app under the current policy.

## 2. Network requests that are not telemetry

A strict no-telemetry rule does not mean that every network packet is prohibited. The following are functional requests explicitly initiated/configured by the user:

1. **DNS filtering:** while the user has started the DNS feature, supported DNS queries are sent to the resolver the user configured. The resolver can see queried names. DNS-over-TLS encrypts the transport to the resolver but does not hide the names from that resolver.
2. **AI analysis:** a request is sent only after the user chooses an allowed task, pastes text and confirms the selected provider. Only the supplied text is attached automatically.
3. **Encrypted sync:** a request is sent when the user configures and invokes sync. The relay receives encrypted packets and routing metadata; it cannot decrypt packet content using the relay database alone.
4. **External links:** when the user opens a policy, app-store page or source link, the browser/OS connects to that destination.
5. **Self-hosted web/relay use:** a user or operator may run a separate backend or relay. Their network and hosting logs are governed by that operator's configuration and notice.

These are user-requested service functions, not hidden analytics. They still disclose the information described in the Privacy Policy and External Services document.

## 3. Local diagnostics

Local aggregate DNS counters, local status state, optional encrypted DNS history, permission comparisons and app-policy review metadata are not uploaded by PrivaCage as telemetry.

The Android VPN service may write short, static diagnostic messages to Android's local system log. Exception objects and stack traces are not intentionally written by the current DNS service code. Android itself, OEM diagnostics, debugging tools or a device-management service may access or collect system logs under their own rules. PrivaCage cannot disable those platform-level behaviours.

## 4. Enforcement

The repository's validate-android-privacy check:
- rejects a set of unreviewed sensitive Android permissions;
- scans the Android manifest, Gradle files and main application source for known analytics/ad/crash SDK and advertising-ID markers; and
- runs in the repository validation workflow.

This static scan is a guardrail, not proof that hand-written telemetry or platform/OEM collection is impossible. Code review must also reject custom tracking endpoints, hidden event queues, telemetry-like network clients and new data collection that bypasses the known SDK list.

## 5. No exceptions by dependency accident

A transitive dependency must not introduce telemetry without review. Before adding an Android dependency, reviewers must check:
- whether it contains analytics, ad, crash, session replay, attribution or remote-diagnostics functionality;
- whether those functions are enabled by default;
- whether it opens network connections;
- whether they can be removed or fully disabled; and
- whether the static CI markers need extending.

A feature that genuinely requires remote diagnostics must be proposed as a policy change, not slipped in as a default SDK dependency.

## 6. Platform boundary

This policy governs PrivaCage code. It cannot promise that Android, an OEM, carrier, DNS resolver, browser, app store, AI provider or hosting provider collects no information. The app's DNS path is not a whole-device VPN and cannot suppress traffic outside its documented coverage.

The Windows local CLI and any future iOS application require their own platform-specific audits before this Android policy can be claimed as enforced there.
