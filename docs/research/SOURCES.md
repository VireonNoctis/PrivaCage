# Research Source Register

**Reviewed:** 25 October 2026. Links point to official platform documentation, primary standards, regulators, law or established privacy-analysis projects. OS and legal sources should be reopened before implementation/release because APIs, store policy and regulations can change.

## Android platform

<a id="s01"></a>
### S01 — Android Developers: VPN guide
https://developer.android.com/develop/connectivity/vpn

Primary implementation guide for `VpnService`, app inclusion/exclusion, tunnel setup and bypass considerations.

<a id="s02"></a>
### S02 — Android Developers: `VpnService` API
https://developer.android.com/reference/android/net/VpnService

Public class and lifecycle methods, including `prepare`, `protect`, always-on and lockdown-related API surface.

<a id="s03"></a>
### S03 — Android Developers: `VpnService.Builder` API
https://developer.android.com/reference/android/net/VpnService.Builder

App allow/disallow lists and virtual interface configuration. The allowed/disallowed app behavior is important for truthful coverage reporting.

<a id="s04"></a>
### S04 — Android Developers: `ConnectivityManager` API
https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,java.net.InetSocketAddress,java.net.InetSocketAddress)

Documents `getConnectionOwnerUid`, supported TCP/UDP tuple inputs, active VPN permission context and invalid-UID result behavior.

<a id="s05"></a>
### S05 — Android Developers: Package visibility filtering
https://developer.android.com/training/package-visibility

Android 11/API 30+ installed-app query restrictions, selective `<queries>` and conditions for `QUERY_ALL_PACKAGES`.

<a id="s06"></a>
### S06 — Android Developers: Privacy checklist
https://developer.android.com/privacy-and-security/about

Resettable identifiers, persistent hardware identifier restrictions and privacy best practices.

<a id="s07"></a>
### S07 — Android Developers: behavior changes for apps targeting Android 13+
https://developer.android.com/about/versions/13/behavior-changes-13

Includes the `AD_ID` permission behavior for Google Play services on apps targeting API 33+.

<a id="s08"></a>
### S08 — Android Developers: Android 13 features/changes
https://developer.android.com/about/versions/13/features

Includes clipboard visual confirmation and other Android 13 behavior changes.

<a id="s09"></a>
### S09 — Android Developers: background body sensors
https://developer.android.com/health-and-fitness/health-services/background-body-sensors

Documents the background body-sensor permission model introduced for Android 13/Wear OS 4 and its restrictions.

<a id="s09a"></a>
### S09a — Android Developers: `AppOpsManager` API
https://developer.android.com/reference/android/app/AppOpsManager

Framework API reference for app-operation inspection and management. Specific operations remain privilege- and API-dependent; the existence of an API does not grant an ordinary third-party app authority to modify arbitrary apps.

## Apple platform

<a id="s10"></a>
### S10 — Apple Developer: `NEPacketTunnelProvider`
https://developer.apple.com/documentation/networkextension/nepackettunnelprovider

Defines packet-tunnel behavior, virtual interface/packet flow and Network Extension entitlement requirement.

<a id="s11"></a>
### S11 — Apple Developer: Network Extensions entitlement
https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension

Enumerates Network Extension provider values including packet tunnel, content filter, app proxy and DNS proxy; availability and distribution restrictions require per-feature review.

<a id="s12"></a>
### S12 — Apple Developer: Configuring network extensions
https://developer.apple.com/documentation/xcode/configuring-network-extensions/

Explains capability configuration, provider families and cases with deployment restrictions.

<a id="s13"></a>
### S13 — Apple Support (Ireland): About App Privacy Report
https://support.apple.com/en-ie/102188

Official user-facing information on data/sensor access and network activity in the previous seven days, report enablement, local encryption/storage and clearing behavior. Published 29 December 2025.

<a id="s14"></a>
### S14 — Apple Developer: App Privacy Details
https://developer.apple.com/app-store/app-privacy-details/

Official app-store privacy disclosure guidance, including data types, purposes, third-party partners and developer responsibility for accuracy.

<a id="s14a"></a>
### S14a — Apple Developer: App Review Guidelines
https://developer.apple.com/app-store/review/guidelines/

Privacy collection/storage/disclosure expectations and app-review policy. Review the current full guidelines before submission.

## Network standards and browser privacy

<a id="s15"></a>
### S15 — IETF RFC 8484: DNS Queries over HTTPS (DoH)
https://www.rfc-editor.org/rfc/rfc8484.html

Standards-track specification describing DNS queries and responses over HTTPS.

<a id="s16"></a>
### S16 — IETF RFC 9849: TLS Encrypted Client Hello (ECH)
https://www.rfc-editor.org/rfc/rfc9849.html

Standards-track ECH specification published in March 2026. Describes encryption of sensitive ClientHello fields such as SNI and explains remaining observable channels such as plaintext DNS/IP.

<a id="s28"></a>
### S28 — MDN: Privacy on the web
https://developer.mozilla.org/en-US/docs/Web/Privacy

Educational documentation on browser privacy and fingerprinting, including browser/device characteristics and mitigations.

<a id="s29"></a>
### S29 — UK ICO: Storage and Access Technologies guidance announcement
https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2026/04/final-storage-and-access-technologies-guidance-published/

Published 29 April 2026. Describes ICO's updated guidance covering cookies, tracking pixels, device fingerprinting and similar technologies in UK legal context.

## Mobile security and privacy frameworks

<a id="s17"></a>
### S17 — Exodus Privacy: What the project does
https://exodus-privacy.eu.org/en/page/what/

Describes tracker-signature and permission reporting for Android apps. Useful reference for public-facing tracker reports and the limits of static SDK analysis.

<a id="s18"></a>
### S18 — Exodus Privacy: FAQ
https://exodus-privacy.eu.org/en/page/faq/

Explicitly notes that detecting a tracker signature is not proof it is active and that the list may contain false positives and false negatives.

<a id="s25"></a>
### S25 — NIST Privacy Framework
https://www.nist.gov/privacy-framework/privacy-framework

Voluntary privacy-risk management framework, version 1.0 (January 2020). Not law or certification.

<a id="s26"></a>
### S26 — OWASP Mobile Application Security Verification Standard (MASVS)
https://mas.owasp.org/MASVS/

Mobile security controls grouped around storage, cryptography, authentication, network communication, platform interaction, code and privacy.

<a id="s27"></a>
### S27 — OWASP Mobile Application Security Testing Guide overview
https://mas.owasp.org/MASTG/0x03-Overview/

Mobile application test context, emphasizing data protection on-device and in network communications.

## Privacy law and regulators

<a id="s19"></a>
### S19 — EU General Data Protection Regulation (GDPR), Regulation (EU) 2016/679
https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679

Primary legal text. See especially Article 12(3) for response timelines and extensions and Article 17 for right to erasure and exceptions. Applies only where its territorial/material scope is met.

<a id="s20"></a>
### S20 — UK Information Commissioner's Office: Right to erasure
https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/

Guidance describing the one-calendar-month general deadline, permitted extensions, identity considerations and exceptions under UK GDPR context.

<a id="s21"></a>
### S21 — California Privacy Protection Agency: CCPA statute effective 1 January 2026 (PDF)
https://cppa.ca.gov/regulations/pdf/ccpa_statute_eff_20260101.pdf

Primary California statutory/regulatory text version published by CPPA for 2026. Review applicable sections and updates before coding legal rules.

<a id="s22"></a>
### S22 — California Privacy Protection Agency: FAQ
https://cppa.ca.gov/faq

Current consumer-facing explanation of timelines, confirmation and possible denial of requests. Consult together with primary text and implementing regulations.

<a id="s23"></a>
### S23 — California Privacy Protection Agency: DROP system requirements
https://cppa.ca.gov/regulations/drop.html

Official system/regulatory information for the Delete Request and Opt-out Platform, including legal effective status. Does not itself establish that a third-party developer has a public API.

<a id="s24"></a>
### S24 — California Privacy Protection Agency: California approves Delete Act regulations
https://cppa.ca.gov/announcements/2025/20251113.html

Announcement describing the state platform and the 2026 schedule for data brokers to retrieve/process requests.

<a id="s12a"></a>
### S12a — FTC: Gravy Analytics / Venntel location data order
https://www.ftc.gov/news-events/news/press-releases/2025/01/ftc-finalizes-order-prohibiting-gravy-analytics-venntel-selling-sensitive-location-data

January 2025 enforcement action relating to sensitive location data and visits to sensitive places.

<a id="s12b"></a>
### S12b — FTC: Mobilewalla location data order
https://www.ftc.gov/news-events/news/press-releases/2025/01/ftc-finalizes-order-banning-mobilewalla-selling-sensitive-location-data

January 2025 finalized order concerning sensitive location data.

<a id="s12c"></a>
### S12c — FTC: Kochava / Collective Data Solutions announcement
https://www.ftc.gov/news-events/news/press-releases/2026/05/ftc-ban-kochava-subsidiary-selling-sensitive-location-data-settle-charges-they-sold-location-data

May 2026 announcement concerning a proposed settlement about sensitive location data. Distinguish allegations/proposed terms from a final adjudicated fact.

## Evidence management note

For a public release, the project should maintain machine-readable source metadata where helpful: `source_id`, title, owner, URL, source type, publication/effective date, last_checked, claims_supported, reviewer and archived snapshot/hash if lawful. Don't copy full legal documents or third-party articles into the repository when a link and concise analysis suffice.