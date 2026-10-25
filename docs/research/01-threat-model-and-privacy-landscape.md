# 01 — Threat Model and Privacy Landscape

**Research status:** baseline synthesis, 25 October 2026  
**Decision this note supports:** what PrivaCage should protect against first, and what it must not claim to solve.

## 1. The problem is a data lifecycle, not a single “tracking” event

A privacy incident commonly spans several stages: a device or app reads a signal; an SDK or app transforms it into an identifier or profile feature; the app sends it to a service; an intermediary combines or resells it; a recipient infers sensitive facts; and the person has little visibility or practical recourse. Device controls mainly influence the first three stages. A local monitor cannot reach inside a remote broker's systems, prove how a recipient used a record, or guarantee deletion from backups.

Regulatory enforcement shows why location-data markets deserve explicit attention. In January 2025, the US Federal Trade Commission finalized orders involving Gravy Analytics/Venntel and Mobilewalla that restricted sales or uses of sensitive location data, including visits to sensitive locations ([S12a](SOURCES.md#s12a), [S12b](SOURCES.md#s12b), [S12c](SOURCES.md#s12c)). In May 2026, the FTC announced a proposed settlement concerning Kochava and its subsidiary over sensitive location data. These proceedings demonstrate concrete risks; they do not prove that every location SDK or every app engages in unlawful conduct.

## 2. Adversaries and failure sources

| Actor or source | Objective or failure | Practical control surface | What PrivaCage cannot promise |
|---|---|---|---|
| Advertising / analytics SDK | Associate activity across apps, devices or sessions | Detect known SDKs in APKs; observe accessible DNS/IP metadata; block known destinations; explain resettable identifier controls | Prove the SDK executed or identify every payload it sent |
| App developer / backend | Collect more data than expected, retain it, or combine it with an account | Static permission/SDK review; network destination history; user-reviewed rights requests | Inspect private server databases or force deletion |
| Data broker | Aggregate and resell identifiers, location or inferred profiles | Help identify broker opt-outs; support official deletion mechanisms; track evidence of requests | Discover every broker holding a person's data or verify every deletion |
| Malicious or deceptive app | Abuse granted permissions, persistence, overlays or network access | Permission education, APK review, local network rules, security checks and safety-sensitive indicators | Reliably label an app “spyware” from one suspicious permission or SDK |
| Physical abuser / coercive monitor | Gain access to a person's device/account and watch for attempts to regain privacy | Safety planning, neutral UI, local processing, sensitive notification options, links to specialist support | Safely remove every monitoring mechanism or assume the device is safe to scan |
| OS / device vendor / carrier | Collect system telemetry outside ordinary app privileges | Explain settings and verified configuration options; document known OEM behavior | Intercept firmware/baseband traffic or disable built-in services on an ordinary app |
| PrivaCage itself | Become a centralized store of device inventory, domains, legal identity or browsing history | Data minimization, local-first design, short retention, no analytics by default, reproducible builds | Claim that “local-only” is true without measuring all network egress |

## 3. Priority threat classes

### A. Cross-app tracking and advertising identifiers — high priority

**Why it matters:** app SDKs can collect app/device events and join them with resettable identifiers, account IDs, network metadata or other data. Android's privacy guidance recommends resettable identifiers and discourages access to persistent hardware identifiers such as IMEI/serial on ordinary apps ([S06](SOURCES.md#s06), [S07](SOURCES.md#s07)).

**Useful response:** explain what an identifier is, whether the build can access it, app/SDK evidence, and where platform settings let the user limit or reset it. Do not claim that resetting the ad ID stops tracking based on account login, IP address, fingerprinting or first-party identifiers.

### B. Sensitive location and inference — high priority

**Why it matters:** location trails can reveal visits to healthcare facilities, religious venues, political gatherings, home/work routines or other sensitive places. A location permission dialog is not a full description of downstream sharing.

**Useful response:** distinguish permission eligibility from observed access and from observed network transmission. Keep exact coordinates out of normal logs. Provide coarse summaries and clear links to system permission controls. Use carefully scoped block rules for known tracking endpoints, while warning that an app may break if blocked.

### C. Network telemetry and undisclosed destinations — high priority, with caveats

**Why it matters:** a local VPN can observe routed packets and, depending on DNS setup, DNS requests. Domain-level information can reveal services and behavioral patterns even if content is encrypted. New domains are not inherently malicious, and a domain can serve analytics, core application features, crash reporting and CDN content simultaneously.

**Useful response:** record the exact level observed (IP, DNS hostname, TLS metadata where visible), provenance, time, app UID confidence, block/allow result and rule version. Apply explainable classifications and never log payloads by default.

### D. Excessive permissions and SDKs in software before installation — high priority

**Why it matters:** APK manifests and SDK signatures can reveal access capability and potentially risky dependencies before a user installs an APK they control. But requested permissions are not the same as exercised permissions, and embedded code may be dormant or dynamically loaded.

**Useful response:** use “requests permission” and “contains SDK signature” language, cite the APK hash/version and scan database version, and show confidence. Avoid a single moral score that collapses unrelated risks.

### E. Data brokers / rights and opt-out friction — high priority

**Why it matters:** even when collection has already happened, a person needs repeatable workflows to contact controllers and registered brokers. California's 2026 framework for the Delete Request and Opt-out Platform (DROP) is a concrete opportunity for a user-guided broker-deletion workflow ([S23](SOURCES.md#s23)).

**Useful response:** maintain jurisdiction-specific templates, collect the minimum identity information, let the user review each destination and request, preserve only chosen evidence, and represent status as “drafted,” “submitted,” “acknowledged,” “response received,” or “outcome unverified.”

### F. Browser fingerprinting and shared-file metadata — medium/high priority

**Why it matters:** browser features can form a fingerprint even when cookies are unavailable; photos and documents can contain GPS, device, author, software and other metadata. Platform-wide fingerprint randomization is not available to an ordinary companion app, but a controlled browser and share-sheet metadata scrubber are technically grounded alternatives ([S28](SOURCES.md#s28), [S29](SOURCES.md#s29)).

### G. Stalkerware and coercive monitoring — high impact, difficult to detect safely

**Why it matters:** an abusive person may install monitoring software, misuse legitimate admin/accessibility/notification privileges, or have account-level access. Detection is imperfect, and a prominent alert, changed setting or new notification can reveal that the person is seeking help.

**Useful response:** build a safety review that describes concrete device indicators and uncertainty, minimizes traces, offers a neutral exit, and avoids automatic removal or alerting anyone. Do not market a heuristic as a definitive stalkerware detector.

## 4. Threat model assumptions

- Initial target is a non-rooted Android device controlled by the person using PrivaCage, with optional root integrations outside the baseline threat model.
- The app itself is not the device owner or an enterprise MDM controller.
- Network traffic may be encrypted; DNS may use DoH/DoT; apps may bypass a local VPN if configuration allows it or route through their own network choices.
- App IDs, IP addresses, domain histories and scan results may themselves be sensitive personal data.
- The app may be used on a shared device or in a coercive household, so ordinary security advice must not assume that visible changes are safe.
- The legal jurisdiction, data controller, applicable law and right exercised must be user-confirmed before submission.

## 5. Success measures

The product should measure verified utility, not count how many warnings it can generate:

1. **Detection precision:** sampled positive alerts have reproducible evidence and a documented false-positive rate.
2. **Attribution coverage:** share of observed flows with a verified app UID; unknown attribution is explicit, not guessed.
3. **Block correctness:** controlled tests show matching traffic was blocked and non-matching traffic was not, for supported protocols.
4. **Privacy preservation:** tests confirm sensitive payloads and exact coordinates are absent from default logs and exported reports.
5. **User comprehension:** users can distinguish capability, observation, inference and successful enforcement.
6. **Rights workflow correctness:** each template has a named legal basis, eligibility caveat, official contact route and deadline rule; sending is not treated as deletion.
7. **Safety:** no default telemetry, no unnecessary remote account, and no notifications that disclose a safety scan unless the user enables them.

## 6. Bottom line

Start with observability PrivaCage can validate: APK metadata and signatures, system-provided permission state, locally routed network metadata, rule outcomes, and transparent request status. Treat root-only API tracing, universal sensor/clipboard surveillance, universal iOS interception, and guaranteed data deletion as unsupported unless a specific reviewed implementation demonstrates otherwise.