# 03 — iOS Platform Capability Audit

**Research status:** official Apple documentation review, 25 October 2026  
**Decision this note supports:** build an honest companion experience rather than promise Android-style system control on iOS.

## 1. Network Extension is not a universal cross-app introspection API

Apple's `NEPacketTunnelProvider` creates a virtual interface and exposes packets routed to that interface through `packetFlow`. It requires the Network Extension entitlement. Apple's Network Extension families have distinct uses: packet tunnel, app proxy, content filter, DNS proxy and DNS settings; some capabilities have platform, entitlement, deployment or supervised-device restrictions ([S10](SOURCES.md#s10)–[S12](SOURCES.md#s12)).

A packet tunnel can support a user-authorized network tunnel and certain network-layer observations. It does not supply arbitrary calls made by other apps into UIKit, Core Location, Contacts, Photos, clipboard, microphone or sensor APIs. Do not construct those events by looking at traffic.

Per-application VPN and content-filter capabilities are not freely interchangeable with a consumer-facing permission toggle. Confirm the exact entitlement, supported configuration and App Store distribution implications for the particular provider type before relying on it. Do not assume a general App Store app can choose and silently control each app's networking identity in the same manner as a managed-device deployment.

## 2. App Privacy Report: useful, but bounded

Apple documents App Privacy Report as a user-visible privacy surface available on iOS/iPadOS 15.2 and later. It reports access to sensitive data/sensors and network activity/domains over the past seven days; it starts collecting after the user enables it, and the report is encrypted and stored on the device. Turning it off clears the report data ([S13](SOURCES.md#s13)).

**Important implementation boundary:** this documentation describes the system report, not a general public API that lets any third-party app directly read all of the report's underlying event database. PrivaCage should not claim that it can automatically ingest the complete report unless an explicitly documented import path becomes available. A user-guided explanation, checklist or user-selected export/import approach is honest. Any import must state that the source is Apple’s report and preserve the report's time window and attribution limits.

App Privacy Report does not cover every possible sensor or network event in all contexts, and domain contact does not prove that the app transmitted a particular personal field. For example, an app can contact a domain because of embedded web content. Use it as a separate, user-provided evidence source, not as a complete ground truth feed.

## 3. App Store privacy labels are disclosures, not measured telemetry

Apple asks developers to disclose data types collected by the app and its third-party partners, whether data is linked to a user, and purposes such as analytics or advertising. The disclosure is maintained by the developer in App Store Connect; Apple requires developers to keep it accurate and up to date ([S14](SOURCES.md#s14)). This makes privacy labels valuable comparative information, but they are not independent runtime verification by PrivaCage.

Use wording such as “developer-disclosed collection includes…” and allow the user to compare it with other evidence sources. Do not treat missing disclosure as definitive proof of no collection, nor an SDK presence as proof the SDK actually transmitted data.

## 4. Permission control on iOS

Use documented user-mediated controls and direct users to iOS Settings for revocation. An ordinary third-party iOS app cannot install a general AppOps shim, inspect another app's binary at installation time, or inject fake sensor/clipboard data into other apps. Do not market this as available via SwiftUI or Network Extension.

If a user imports screenshots/reports manually, warn before extraction that screenshots can contain app names, domains, timestamps and other sensitive context. Prefer on-device parsing, review-before-save and a delete-import action. Store original reports only when the user explicitly asks to retain them.

## 5. What the iOS version can ship credibly

| Feature | Feasible path | Claim boundary |
|---|---|---|
| Privacy education and settings guide | Native UI linking to platform settings; hand-curated evidence notes | Guidance, not an actual permission toggle |
| App Privacy Report assistant | Explain how to enable and interpret Apple's report; optional user-directed import if safely implemented | Not a complete live feed or automatic read of private system report data |
| Privacy label comparison | Display Apple's published disclosure with version/date context | Developer disclosure, not independently measured behavior |
| Data-rights request engine | Local templates, user review, submission links/email where supported, response tracking | Cannot force remote deletion or know that a request was honored without evidence |
| EXIF/document metadata scrubber | User-selected file processing and re-export | Scrubs the output file types the implementation explicitly tests; not every file format automatically |
| Network monitor via Network Extension | Only after entitlement, routing and App Store path are validated | Network packet visibility only; no general sensor/API audit |
| Per-app network identity/control | Only with supported Apple configuration/entitlement and deployment model | Do not promise blanket consumer control before validation |

## 6. Distribution gate and security review

Before implementing an iOS network feature, create a short proof-of-capability prototype and verify entitlement approval, user consent, routing behavior, behavior when switching networks, packet size limits, background execution, and App Review requirements. Keep the first iOS milestone useful even if packet-level monitoring is not approved: privacy education, local file metadata cleaning, privacy label comparison and the legal workflow do not depend on pretending the OS is open.

## 7. Acceptance criteria

- No iOS screen claims access to another app's API calls or binary unless a documented entitlement/API enables the exact signal.
- App Privacy Report information is labelled “Apple report” and its seven-day window is preserved.
- Every network monitoring prototype identifies the exact Network Extension provider type and entitlement.
- The UI opens Settings rather than impersonating a native permission toggle.
- App Store disclosures, imported sources and measured observations remain different fields in the internal schema.