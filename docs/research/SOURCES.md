# Research Source Register

**Research register baseline:** 25 October 2026. **Android monitoring-access, cellular-security and device-posture sources rechecked:** 7–8 November 2026. Links point to official platform documentation, primary standards, regulators, law or established privacy-analysis projects. OS and legal sources should be reopened before implementation/release because APIs, store policy and regulations can change.

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

<a id="s09b"></a>
### S09b — Android Developers: Android Keystore system
https://developer.android.com/privacy-and-security/keystore

Documents key-material protection, non-exportable Keystore keys, restrictions on permitted cryptographic operations, and available authentication controls. Hardware-backed protection varies by device and implementation; do not describe every generated key as hardware-backed.

<a id="s09j"></a>
### S09j — Android Developers: Android Keystore and Java security exceptions
https://developer.android.com/privacy-and-security/keystore
https://developer.android.com/reference/java/security/GeneralSecurityException
https://developer.android.com/reference/java/security/ProviderException

Checked 13 November 2026. Android Keystore uses the standard Java `KeyStore` and `KeyGenerator` APIs. Key-access failures are represented by `GeneralSecurityException` subclasses; JCA provider faults can also surface as `ProviderException`, which is a runtime exception. PrivaCage converts only these expected key-access/provider failures into explicit I/O errors so encrypted-store callers can preserve existing ciphertext and report the failure. Unrelated runtime/programming errors remain visible.

<a id="s09k"></a>
### S09k — NIST SP 800-38D: GCM authenticated encryption and revision status
https://csrc.nist.gov/pubs/sp/800/38/d/final
https://csrc.nist.gov/News/2026/gcm-and-gmac-block-cipher-modes-of-operation

SP 800-38D (November 2007) specifies GCM as authenticated encryption with associated data; authenticated decryption is required before an existing envelope is trusted. Checked 13 November 2026. NIST's second pre-draft revision notice was published 1 June 2026, with comments due 31 July 2026; the 2007 final remains the final publication listed by NIST at this check. Recheck the revision before release. This PrivaCage change does not alter GCM parameters, nonce generation, or tag length.

<a id="s09c"></a>
### S09c — Android Developers: `SharedPreferences.Editor` API
https://developer.android.com/reference/android/content/SharedPreferences.Editor

Documents atomic editor updates, synchronous `commit()` and its persistence result, and asynchronous `apply()` behavior. Relevant to preserving DNS history while migrating the old plaintext preference.

<a id="s09d"></a>
### S09d — Android Developers: Save simple data with SharedPreferences
https://developer.android.com/training/data-storage/shared-preferences

Android's guidance warns about blocking, durability, and consistency trade-offs in SharedPreferences and recommends considering DataStore or Room for new storage needs. PrivaCage retains its existing small preferences store here; this migration is not a general recommendation to start new persistence on SharedPreferences.

<a id="s09e"></a>
### S09e — Android Developers: AccessibilityManager API
https://developer.android.com/reference/android/view/accessibility/AccessibilityManager#getEnabledAccessibilityServiceList(int)

Documents the enabled accessibility-service list returned for a requested feedback-type mask. PrivaCage requests FEEDBACK_ALL_MASK and treats the result as an OS-exposed list, not evidence of intent or service behavior.

<a id="s09f"></a>
### S09f — Android Developers: DevicePolicyManager API
https://developer.android.com/reference/android/app/admin/DevicePolicyManager#getActiveAdmins()

Documents the active device-administrator component list. The result is scoped to the calling user/profile and does not identify who controls a device.

<a id="s09g"></a>
### S09g — Android Developers / AOSP: notification-listener access setting
https://developer.android.com/reference/android/provider/Settings.Secure
https://developer.android.com/reference/android/app/NotificationManager#isNotificationListenerAccessGranted(android.content.ComponentName)
https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/provider/Settings.java
https://android.googlesource.com/platform/packages/apps/Settings/+/refs/heads/main/src/com/android/settings/notification/NotificationAccessSettings.java

The public Settings.Secure.getString getter returns null when a value is not present, and the Settings.Secure class describes secure settings as readable by applications and not writable by ordinary apps. However, AOSP declares the ENABLED_NOTIFICATION_LISTENERS setting key itself @hide and deprecated; it is an implementation detail, not a stable public SDK contract. The AOSP Settings notification-access screen and NotificationManagerService use it to enumerate approved listener components. The public NotificationManager.isNotificationListenerAccessGranted(ComponentName) method is limited to a listener belonging to the calling app, so it does not replace cross-app enumeration. PrivaCage reads only the component setting and never notification content; a null value is reported unavailable rather than treated as an empty list. OEM/platform behavior requires representative device validation.

<a id="s09h"></a>
### S09h — Android Developers: ConnectivityManager and NetworkCapabilities
https://developer.android.com/reference/android/net/ConnectivityManager#getActiveNetwork()
https://developer.android.com/reference/android/net/ConnectivityManager#getNetworkCapabilities(android.net.Network)
https://developer.android.com/reference/android/net/NetworkCapabilities

Documents the active default network, its capabilities, and TRANSPORT_VPN. This supports a statement about the current default network only; it does not identify the VPN owner or every per-app/non-default route.

<a id="s09i"></a>
### S09i — Android Developers: Settings actions
https://developer.android.com/reference/android/provider/Settings

Documents OS-owned settings handoffs for accessibility, notification-listener, security and VPN settings. ACTION_APPLICATION_DETAILS_SETTINGS opens one package's app-info page using a package: URI; availability can vary by Android build, so callers must handle a missing activity. PrivaCage uses this only on an explicit user tap and does not query application labels or mutate the package.

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

<a id="s30"></a>
### S30 — CalPrivacy: Delete Request and Opt-Out Platform (consumer landing page)
https://privacy.ca.gov/drop/

Consumer-facing official entrypoint, eligibility summary, link to the DROP service, data-handling overview, November 2026 initial-cycle update, recurring 45-day broker cycle and possible 90-day status-update window. Checked 8 November 2026.

<a id="s31"></a>
### S31 — CalPrivacy: How DROP works
https://privacy.ca.gov/drop/how-drop-works/

Consumer guidance for eligibility, profile creation, submission, DROP ID handling, status meanings, the 90-day status-reporting window and recurring 45-day re-check/deletion cycle. Checked 8 November 2026.

<a id="s32"></a>
### S32 — CalPrivacy: Help with DROP
https://privacy.ca.gov/drop/help-with-drop/

Official consumer help covering residency verification, privacy handling, the instruction not to share a DROP ID, status-update timing and requests made on another person's behalf. Checked 8 November 2026.

<a id="s33"></a>
### S33 — Android Open Source Project: Disable 2G
https://source.android.com/docs/security/features/cellular-security/disable-2g

Documents false-base-station downgrade risk, the 2G radio-level protection capability, emergency-call behavior, and the privileged authority required for applications to change allowed network types. Checked 8 November 2026.

<a id="s34"></a>
### S34 — Android Open Source Project: 2G connectivity toggle
https://source.android.com/docs/security/features/cellular-security/toggle-2g

Documents the per-SIM 2G control and Android 16 label/default-state changes. The switch label/description—not its visual position—must be used to confirm the intended protection state. Checked 8 November 2026.

<a id="s35"></a>
### S35 — Android Open Source Project: Mobile network security
https://source.android.com/docs/security/features/cellular-security/mobile-network-security

Documents Android 16 Safety Center notifications for unencrypted connections and device-identifier disclosures, the compatible modem/IRadio requirements, per-SIM 2G entry points and the notifications toggle's OFF default. Checked 8 November 2026.

<a id="s36"></a>
### S36 — Android Developers: TelephonyCallback and DisplayInfoListener
https://developer.android.com/reference/android/telephony/TelephonyCallback
https://developer.android.com/reference/android/telephony/TelephonyCallback.DisplayInfoListener

Documents the API 31 callback model, registration lifecycle, and permission requirements where applicable. DisplayInfoListener does not document a runtime phone-state permission requirement. Checked 8 November 2026.

<a id="s37"></a>
### S37 — Android Developers: TelephonyDisplayInfo
https://developer.android.com/reference/android/telephony/TelephonyDisplayInfo

Documents the packet-switched network type and override type. getNetworkType() reports the actual packet-switched network type the device is camped on; the API is display-oriented and does not expose the radio's cipher/encryption algorithm. Checked 8 November 2026.

<a id="s38"></a>
### S38 — Android Developers: AccessibilityService
https://developer.android.com/reference/android/accessibilityservice/AccessibilityService

States that Accessibility services should only be used to assist users with disabilities and receive user-interface AccessibilityEvents. The API does not provide cellular radio or cipher-state control. Checked 8 November 2026.

<a id="s39"></a>
### S39 — Android Developers: Settings actions
https://developer.android.com/reference/android/provider/Settings

Documents ACTION_WIRELESS_SETTINGS for Wi-Fi/Bluetooth/mobile-network controls and ACTION_SECURITY_SETTINGS for security/location privacy settings. OEM-specific navigation remains controlled by Android Settings. Checked 8 November 2026.


<a id="s40"></a>
### S40 — Android Open Source Project: Android Security Bulletin — November 2026
https://source.android.com/docs/security/bulletin/2026/2026-11-01/

Published 2 November 2026. Defines the 2026-11-01 and 2026-11-05 patch levels; the latter addresses all issues listed in both November patch-level groups. Includes critical Framework and kernel issue severity descriptions. Applicability depends on OS version/device/vendor updates. Checked 8 November 2026.

<a id="s41"></a>
### S41 — Android Developers: Build.VERSION
https://developer.android.com/reference/android/os/Build.VERSION

Documents SECURITY_PATCH as the user-visible security patch level string. It is a reported patch date, not a complete statement about vendor, modem or Google Play system update freshness. Checked 8 November 2026.

<a id="s42"></a>
### S42 — Android Developers: KeyguardManager
https://developer.android.com/reference/android/app/KeyguardManager#isDeviceSecure()

Documents isDeviceSecure(), which reports whether the device is secured by a PIN, pattern or password credential. It does not assess credential strength or device integrity. Checked 8 November 2026.

<a id="s43"></a>
### S43 — Android Developers: Settings.Global
https://developer.android.com/reference/android/provider/Settings.Global

The ADB_ENABLED and DEVELOPMENT_SETTINGS_ENABLED values are documented to return 0 for all third-party apps. PrivaCage must not infer that debugging is disabled from those reads. Checked 8 November 2026.

<a id="s44"></a>
### S44 — Android Developers: PackageManager.canRequestPackageInstalls
https://developer.android.com/reference/android/content/pm/PackageManager#canRequestPackageInstalls()

Documents the install-request permission state for the calling package only. The check requires REQUEST_INSTALL_PACKAGES and is not a device-wide inventory of all packages that can request installation. Checked 8 November 2026.

<a id="s45"></a>
### S45 — Google Play Help: Use Google Play Protect
https://support.google.com/googleplay/answer/2812853?hl=en

Explains Play Protect app checks, scanning of apps from other sources, warnings/removal, default state on Google Mobile Services devices, how to review its setting, and information Google may receive as part of harmful-app detection. Checked 8 November 2026.

<a id="s46"></a>
### S46 — Android Open Source Project: Verified Boot device state
https://source.android.com/docs/security/features/verifiedboot/device-state

Documents LOCKED and UNLOCKED device states and bootloader warning/integrity behavior. It does not grant a normal third-party app a stable public API to read undocumented boot properties. Checked 8 November 2026.

<a id="s47"></a>
### S47 — Android Open Source Project: File-based encryption
https://source.android.com/docs/security/features/encryption/file-based

Documents file-based encryption, Direct Boot and the requirement for devices launching with Android 10+ to use file-based encryption. This does not prove every OEM backup or app export is encrypted. Checked 8 November 2026.

<a id="s48"></a>
### S48 — Android Developers: Tapjacking
https://developer.android.com/privacy-and-security/risks/tapjacking

Documents full and partial occlusion, overlay risks, Android 12 mitigations and the remaining partial-occlusion considerations. Checked 8 November 2026.

<a id="s49"></a>
### S49 — Android Developers: android:exported
https://developer.android.com/privacy-and-security/risks/android-exported

Documents how exported activities, services, receivers and providers can be called by other apps and the importance of explicit exported attributes. Checked 8 November 2026.

<a id="s50"></a>
### S50 — Android Developers: WebView native bridges
https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges
https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion

Documents risks from exposing JavaScript/native bridges to untrusted content, unsafe local-file access and enabling unnecessary JavaScript. Checked 8 November 2026.

<a id="s51"></a>
### S51 — Android Developers: Android 13 privacy and security changes
https://developer.android.com/about/versions/13/summary
https://developer.android.com/about/versions/13/behavior-changes-all

Documents notification permission and clipboard-sensitivity behavior changes introduced in Android 13. Checked 8 November 2026.

<a id="s52"></a>
### S52 — Android Developers: Settings actions
https://developer.android.com/reference/android/provider/Settings

Documents system-owned handoffs including ACTION_APPLICATION_DEVELOPMENT_SETTINGS and ACTION_SYSTEM_UPDATE_SETTINGS. OEM navigation and availability remain system-controlled. Checked 8 November 2026.


<a id="s53"></a>
### S53 — Google Android Help: Protect your personal data against theft
https://support.google.com/android/answer/15146908?hl=en-GB

Consumer guidance for Theft Detection Lock, Offline Device Lock, Failed Authentication Lock, Identity Check, Remote Lock requirements and feature/device availability. Checked 8 November 2026.

<a id="s54"></a>
### S54 — Android Developers: Advanced Protection Mode
https://developer.android.com/privacy-and-security/advanced-protection-mode

Documents Android 16 Advanced Protection Mode, its at-risk-user focus, and system mitigations including disabling 2G/WEP, blocking sideloading, forensic logging, unknown-call restrictions and messaging link protection. Also documents the separate QUERY_ADVANCED_PROTECTION_MODE permission and AdvancedProtectionManager API. PrivaCage reads only the overall mode on supported builds; device-specific USB Protection and optional Intrusion Logging remain manual. Last updated 29 July 2026; checked 8 November 2026.

<a id="s55"></a>
### S55 — Google Android Help: Protect your Android device from USB threats with Advanced Protection Mode
https://support.google.com/android/answer/16778864?hl=en-GB

Documents USB Protection on Pixel 6 and later. With the device locked, it prevents new USB data connections until the device is unlocked; Device Protection enables it as part of Advanced Protection. Checked 8 November 2026.

<a id="s56"></a>
### S56 — Google Android Help: Improve device security with Advanced Protection for Android
https://support.google.com/android/answer/16339980?hl=en-GB

Consumer setup guidance for Android Device Protection, the requirement for a screen lock, possible reboot during setup and optional Intrusion Logging during enrollment. Checked 8 November 2026.


<a id="s57"></a>
### S57 — Android Developers: AdvancedProtectionManager API
https://developer.android.com/reference/android/security/advancedprotection/AdvancedProtectionManager

Added in API level 36. isAdvancedProtectionEnabled() reads the overall Advanced Protection Mode enabled state and requires QUERY_ADVANCED_PROTECTION_MODE; the manager also offers a callback for state changes. The overall state does not prove that every individual device protection feature is available or active. Checked 8 November 2026.

<a id="s58"></a>
### S58 — Android Open Source Project: Android 16 framework manifest, QUERY_ADVANCED_PROTECTION_MODE
https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/core/res/AndroidManifest.xml

Android 16 declares QUERY_ADVANCED_PROTECTION_MODE with protection level normal and the android.security.aapm_api feature flag. The same manifest separately declares Intrusion Detection read/manage permissions as signature|privileged; they are not granted to ordinary apps. Checked 8 November 2026.

## Evidence management note

For a public release, the project should maintain machine-readable source metadata where helpful: `source_id`, title, owner, URL, source type, publication/effective date, last_checked, claims_supported, reviewer and archived snapshot/hash if lawful. Don't copy full legal documents or third-party articles into the repository when a link and concise analysis suffice.

<a id="s59"></a>
### S59 — Have I Been Pwned: API documentation (Pwned Passwords and account search)
https://haveibeenpwned.com/API/V3

The official API documentation distinguishes account-breach search from Pwned Passwords. Account search by email requires an API key; email hash-range k-anonymity is a subscription feature exposed through the IncludesKAnon capability. Pwned Passwords is separately available without a subscription, publishes SHA-1 and NTLM password-hash sets; the implemented SHA-1 path encodes input as UTF-8, supports five-character hash-prefix range lookup, and documents downloading the complete password-hash corpus for offline use. The Pwned Passwords corpus is not an email/account breach database. Checked 14 November 2026.

<a id="s60"></a>
### S60 — Have I Been Pwned: Pwned Passwords
https://haveibeenpwned.com/Passwords

Explains the purpose and scope of the Pwned Passwords dataset, its k-anonymity API, and the official option to download the corpus for offline use. It explicitly cautions that a password not found in the loaded dataset is not necessarily a good password. Checked 14 November 2026.

<a id="s61"></a>
### S61 — Have I Been Pwned: Pwned Passwords Downloader
https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader
https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader/blob/9939f083fdf05c07d83e3dbbe156feda1a781fa0/src/HaveIBeenPwned.PwnedPasswords.Downloader/Program.cs
https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader/blob/9939f083fdf05c07d83e3dbbe156feda1a781fa0/README.md

The official downloader's directory mode writes one file per five-character uppercase SHA-1 prefix (PREFIX.txt). Each non-empty line contains the full 40-character uppercase hash, a colon, and its occurrence count. It also writes sha1.index with prefix/ETag pairs for conditional refresh; the index is not a completeness manifest. The downloader verifies each downloaded range against the API's Content-MD5 header and atomically replaces range files. The inspected upstream commit 9939f083fdf05c07d83e3dbbe156feda1a781fa0 was published 12 November 2026. Checked 14 November 2026.
