# 14 — Initial Concept Assumption Audit

**Audited against:** supplied initial PrivaCage README concept and official API/legal materials checked 25 October 2026.  
**Purpose:** explicitly record important corrections; the original concept should not be treated as a verified implementation spec.

## High-impact assumptions requiring correction

| Initial concept statement / implication | Research outcome | Required wording or architecture change |
|---|---|---|
| “Live Activity Log” shows network calls, sensor reads, clipboard grabs for every app via VPN | A VPN exposes routed packets, not arbitrary app API calls. Other signals require independent documented APIs or privileged instrumentation. | Split the log into `network_observation`, `permission_state`, `user_import`, and any separately supported platform event. Do not invent sensor/clipboard event types. |
| `VpnService` plus `AccessibilityService`/Xposed hooks can intercept `connect()`, location APIs, clipboard APIs and sensor registration | `VpnService` is network-layer. Accessibility is not a general-purpose API-call hook. Xposed/root is a separate privileged and device-specific system. | Stock build: routed network telemetry. Optional root module: separately tested instrumentation. Do not represent either as universal. |
| `AppOpsManager` shim offers granular third-party permission toggles on a normal device | Cross-package AppOps changes require appropriate authority; ordinary apps cannot bypass Android's permission model at will. | Use Settings handoff and verified re-read for stock build. Gate privileged changes behind a real root/system capability. |
| `PackageManager.setComponentEnabledSetting` can act as general per-app control | It is not a blanket permission bypass; its practical authority must be confirmed for the component/package and OS. | Do not use it as a fake substitute for revoked permissions or app network rules. |
| Fake/empty GPS/contact/clipboard/sensor data can be injected into arbitrary third-party apps | Typically requires root, system integration, compatible hooks or app cooperation. | Mark **NOT YET FUNCTIONAL — requires a supported root/system integration** until a tested implementation exists. |
| Panic Mode can disable all non-essential permissions and isolate every app immediately | Stock code cannot generally rewrite other apps' permissions. VPN rules can affect only traffic routed through the active VPN. | Panic mode should enforce the subset actually supported (for example, active VPN rules), show excluded/uncontrolled surfaces and use Settings for the rest. |
| A VPN can identify all app network events and all domains | App attribution can be unknown; encrypted DNS, ECH, hard-coded IPs and shared infrastructure reduce domain visibility. | Store attribution and hostname provenance; allow `unknown`/`IP-only`; avoid “all”/“every.” |
| Static APK scan shows exactly which trackers run and collect data | Static SDK and string matches show embedded indicators, not execution or exfiltration. Signatures miss unknown/dynamic/obfuscated code. | Label `contains SDK signature` and `endpoint string candidate`; runtime observation is separate. |
| Pre-install scanner can inspect any app before store installation | A user-selected APK can be scanned. An ordinary app cannot transparently intercept every Play/App Store installation. Package visibility is constrained on recent Android versions; iOS restricts third-party binary inspection. | Describe as “scan an APK you select” unless a supported distribution integration is proven. |
| iOS companion can directly read App Privacy Report and provide live cross-app telemetry | Apple documents a user-facing report, but does not document a general public API for arbitrary third-party apps to read its full report database. | Start with user-guided interpretation; optional import only via a confirmed supported path. Network Extension is a separate entitlement-backed feature. |
| The rights engine can auto-send and track all requests uniformly | Submission methods, controller identities, eligibility, verification and deadlines vary. GDPR is one month, not a fixed 30 days; California uses its own scope and deadlines. | Version jurisdiction templates and require review before sending; open web forms are not submission confirmation. |
| GDPR requests always have 30 days and CCPA always has 45 | GDPR/UK GDPR generally uses a calendar month with possible extension; California's 2026 rule includes acknowledgement and response deadlines, with conditions for extension. | Use law-specific deadline functions and explicit response/extension states. Add current legal review date. |
| Recommended apps are inherently private because listed in the directory | Dependencies, ownership, policies and behavior change; static scanning and developer claims have limits. | Evidence level, caveats, review date, second review where available, changelog and delist process. |
| A consent receipt ledger is “evidence” of everything an app did | It can record PrivaCage's own observations/settings history; it cannot establish missing telemetry or prove remote deletion. | Define scope: evidence of recorded events and user actions, not comprehensive or legally conclusive proof. |
| Normal vs CS verbosity affects only display | Correct architecture is to store structured events once and render different views; verbose mode must not silently gather more data. | Implement one normalized event schema; verbosity changes formatting only. |
| “No data leaves the device” can be assumed because a VPN tunnel is local | DNS resolution, DB updates, crash reports, analytics or optional services can still generate outbound traffic. | Verify all egress via network capture, include the update/check domains and let users see optional connections. |

## Claims to retain, but narrow

- A local VPN can be a powerful way to observe/block routed network traffic; it is not a general app behavior tracer or anonymity provider.
- APK analysis can help users understand declared capability and known SDK signatures before installation; it cannot guarantee safety.
- A legal request generator can reduce paperwork and track correspondence; it cannot force a remote database operation.
- Root/ROM integrations may enable deeper inspection/control on particular configurations; they increase risk, require compatible APIs and cannot be advertised as universally reliable.
- iOS can still offer meaningful privacy utilities even if full cross-app monitoring is unavailable: education, user-directed reports, file metadata cleaning and rights-request assistance.

## Non-negotiable engineering gate

A feature is not done because a button, class or dashboard card exists. Before shipping, identify the real OS/API source, execute the action on a test device, verify the result from an independent observable when feasible, record unsupported conditions, and ensure the UI reports failure honestly. Any remaining gap must be labelled `NOT YET FUNCTIONAL — requires: <exact blocker>` at the feature boundary and in the release notes.