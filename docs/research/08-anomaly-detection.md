# 08 — Explainable, On-Device Anomaly Detection

**Research status:** engineering synthesis, 25 October 2026  
**Decision this note supports:** alert on meaningful changes without assigning malicious intent from weak signals.

## 1. Detection is a change in observed behavior, not proof of harm

A behavioral baseline can record a set of network destinations, permission states where the OS exposes them, and limited activity patterns for each app. An anomaly means the new observation differs from the baseline. It does **not** by itself prove that personal data was collected, transmitted, sold or misused.

Examples of benign causes include an app update, a new feature, a CDN migration, an embedded web page, a user-triggered upload, a new authentication provider, or a time-zone/network change. The product should present explanations and evidence rather than a black-box “spyware score.”

## 2. Signals worth baselining

**Useful if observed reliably:**

- A new hostname or ASN/IP prefix in a verified app-attributed flow.
- A known tracker destination appearing for the first time after an app update.
- A change in platform-reported permission state.
- A new manifest permission or SDK signature after an APK version changes.
- Repeated background network activity outside an app's prior pattern, where foreground/background state is actually available.
- An unexpected VPN/service or sensitive privilege that the user can verify in system settings.

**Weak or unsafe by themselves:**

- A connection at 03:00.
- A new domain not in a tracker list.
- A high number of requests.
- A library name that sounds suspicious.
- An IP address in a different country.
- A claimed access event synthesized from VPN packets.

Timing is especially easy to overinterpret: background sync, scheduled backup, push notifications and server updates can all happen outside typical waking hours. Network location and geography may be inaccurate behind CDNs, cloud providers or VPNs.

## 3. Keep baselines bounded and local

Recommended baseline structure:

- One rolling summary per app or UID where attribution is verified.
- Recent destination set and frequency bands rather than full URL/content history.
- Separate app versions and tracker DB versions; reset or fork a baseline on a major upgrade.
- Local expiration and user-visible clear/reset controls.
- A “learning” period and visible coverage estimate.
- No cross-user or cloud aggregation by default.

Prefer summaries like “first seen on 2026-10-25” and “3 sessions over 7 days” to storing raw packet timelines indefinitely. If raw event history is needed for troubleshooting, make retention short and clear.

## 4. Detection pipeline

1. Accept only events with valid source provenance.
2. Normalize event time, source, attribution confidence, rule/database versions and platform coverage.
3. Deduplicate repeated events and ignore known noise where there is a documented reason.
4. Compare to a per-app/version baseline.
5. Generate a reason code (for example, `NEW_HOSTNAME`, `SDK_SIGNATURE_CHANGE`, `PERMISSION_STATE_CHANGED`).
6. Apply a simple deterministic severity rule based on evidence type and recurrence—not intent.
7. Present a short explanation, evidence, uncertainty and next safe action.
8. Allow “expected,” “investigate,” and “mute this rule” feedback; record feedback locally and make it reversible.

A first release should use deterministic rules and simple rolling counters. Machine learning is not a requirement. If later considered, it must outperform a documented baseline on held-out, device-diverse data and expose calibration/false-positive information. Do not upload user traffic histories to build a model.

## 5. Severity and message examples

| Evidence | Suggested presentation | Avoid |
|---|---|---|
| Known tracker signature in user-selected APK | “Known SDK signature found in the scanned package; activity is not confirmed.” | “This SDK stole your data.” |
| New DNS hostname observed, attribution verified | “This app contacted a new hostname. We don't yet know its purpose.” | “Unknown spy server detected.” |
| Domain rule matched and packet dropped | “Blocked by rule X; 4 matching requests were dropped.” | “All tracking from this app is stopped.” |
| Permission state changed in Android Settings | “Location permission changed to ‘while in use’ at the time recorded.” | “The app was spying before this change.” |
| Unattributed IP flow | “Network traffic observed; app attribution was unavailable.” | Attach it to the foreground app |
| Several weak signals together | “Review recommended: these observations differ from the recent baseline.” | “Malicious behavior confirmed.” |

## 6. Explainability contract

Every alert must answer:

- What exactly was observed?
- Which component observed it (manifest parser, DNS monitor, OS state, user import)?
- When and under what app/version/network conditions?
- What is the confidence level and what is unknown?
- What benign explanations are plausible?
- What action can the user safely take?
- What happens if they ignore, mute or block it?

The alert should link to source evidence and allow a correction report. Suppressing repeated alerts must not silently disable the underlying protection rule without clearly saying so.

## 7. Evaluation

Build synthetic test fixtures and consented lab devices with known activity. Evaluate precision/recall only when ground truth exists. Separate metrics by event type, Android version, OEM, connectivity conditions and attribution quality. Include quiet benign apps, frequently updating apps, content-heavy apps and known analytics SDK test fixtures. Report missing visibility separately from zero anomalies.

Minimum acceptance tests:

- App update introduces a legitimate CDN and does not produce a high-confidence malicious label.
- New hostname not on any list produces an investigation notice, not a malware verdict.
- Unknown attribution is not included in an app's baseline.
- A known blocked host does not generate a “successful blocking” alert if the VPN was inactive.
- Clearing a baseline actually deletes the stored summary and prevents old state from recreating alerts.
- The user can inspect the specific observed event behind an alert.