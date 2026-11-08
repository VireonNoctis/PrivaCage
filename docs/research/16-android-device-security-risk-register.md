# 16 — Android Device and Application Security Risk Register

**Research status:** Android platform and security-bulletin review, 8 November 2026  
**Purpose:** identify Android security risks PrivaCage can help users review on an ordinary, non-rooted device, distinguish direct OS signals from user reports, and document controls that remain outside a normal app's authority.

This is engineering research, not a malware verdict or a promise that a handset is safe. Android version, manufacturer, carrier, modem, regional firmware and enterprise-management configuration affect which controls exist.

## 1. Executive findings

Android already contains strong layers—application sandboxing, file-based encryption, verified boot, permission controls, Google Play Protect on devices with Google Mobile Services, and system security updates. Those layers reduce risk but do not make every device equally current or every app trustworthy.

The most useful stock-app approach is:

1. Show a small number of direct signals that Android explicitly exposes.
2. Link users to the system screen that owns each security setting.
3. Let users record what they personally checked, but label it as user-reported.
4. Preserve “unknown”, “not supported” and “unavailable” as real outcomes.
5. Avoid hidden-property scraping, global package inventories, Accessibility access, root-only assumptions or a single “secure” score.

The first implementation added here follows that approach: an encrypted local checklist, direct screen-lock and security-patch signals, and Settings handoffs for 2G, native mobile-network alerts, system updates and Developer options.

## 2. Current security context: November 2026

The Android Security Bulletin for November 2026 was published on 2 November 2026. It defines two relevant patch levels:

- 2026-11-01 addresses the issues assigned to that patch level.
- 2026-11-05 addresses the issues assigned to the later level and all previous patch levels in that bulletin.

The November bulletin describes a critical Framework vulnerability that could allow remote code execution without additional execution privileges or user interaction. Its later patch-level section also includes critical kernel privilege-escalation issues involving Bluetooth and pKVM. These are bulletin-level severity statements, not evidence that a particular handset is vulnerable or that exploitation is occurring. Applicability depends on the Android version, device build and vendor update. Device manufacturers also publish device- and chipset-specific bulletins.

Build.VERSION.SECURITY_PATCH exposes Android's user-visible security patch date. It is useful evidence, but it is not a complete currentness verdict: vendors may have additional component updates, Google Play system updates are distinct, and devices have different supported release schedules. PrivaCage shows the reported string and asks the user to inspect their own manufacturer's update channel; it does not embed a monthly cutoff that will become stale.

## 3. Risk register

### R01 — Cellular downgrade and unencrypted-network exposure

**Threat:** a false base station may try to move a phone onto a legacy cellular network, including GSM 2G. A reported 2G data-network type is a warning signal, not proof of a rogue cell or an unencrypted radio link.

**Useful controls:** Android 12+ per-SIM 2G network protection on supported modems; Android 16 native Mobile network security notifications for unencrypted connections and identifier disclosures on compatible modems; review every active SIM/eSIM.

**PrivaCage coverage:** the experimental foreground callback reports the default subscription's packet-data network type; this checklist records user confirmation of the per-SIM setting and native alerts.

**Boundary:** no normal third-party API exposes the modem cipher state or a universal rogue-base-station verdict. Coverage of voice service, every SIM, modem firmware and OEM behavior is not established by the current callback. See research note 15.

### R02 — Missing or delayed security updates

**Threat:** a device remains exposed to flaws already addressed upstream because the OEM, carrier, regional firmware or device support window has not delivered a fix.

**Evidence:** Android's reported security patch date, Android version and the manufacturer's device-specific release notes. The November 2026 bulletin demonstrates why patch levels matter: the 2026-11-01 and 2026-11-05 levels cover different issue groups.

**User action:** check the Android system update screen and the manufacturer's official support/update page. Compare the device's reported patch date with the applicable Android and vendor bulletins.

**PrivaCage coverage:** displays Build.VERSION.SECURITY_PATCH as a direct platform-reported value and links to Android system-update settings and the current bulletin index.

**Boundary:** PrivaCage does not know every vendor build's backport list, modem firmware status, support end date or staged OTA rollout. It does not claim “up to date” from a date comparison alone.

### R03 — Unlocked bootloader or weakened Verified Boot

**Threat:** an unlocked bootloader can permit a modified OS to boot. Verified Boot establishes a chain of trust from a hardware-protected root of trust through bootloader and verified partitions; rollback protection helps prevent booting older vulnerable builds.

**User action:** notice boot-time unlock/integrity warnings; only unlock or install alternative firmware when the user intentionally understands the consequences and has a device-specific, trusted installation plan. A managed/work device may have an administrator-controlled configuration.

**PrivaCage coverage:** documentation and user education only.

**Boundary:** a normal third-party app must not read undocumented ro.boot properties and turn them into a verdict. Reliable device-integrity attestation requires a separate API, trust model, freshness challenge, server/privacy design and validation. It is not implemented here.

### R04 — Weak or absent screen lock and physical device access

**Threat:** when a device is lost or handled by someone else, a weak or absent lock credential can make local data and account sessions easier to access. Android file-based encryption protects data at rest, but access after unlock and the device's credential/hardware implementation still matter.

**Useful signal:** KeyguardManager.isDeviceSecure() tells an ordinary app whether Android reports a secure lock credential configured.

**PrivaCage coverage:** reads this boolean and reports configured / not configured / unavailable.

**Boundary:** this does not measure PIN entropy, guess resistance, biometric strength, coercion, shoulder-surfing, recovery flows, or whether every app properly protects its own data. It is not a cryptographic proof of device integrity.

### R05 — Misused Accessibility, notification-listener, administrator or VPN access

**Threat:** powerful access can be misused by unwanted software, but the same access is essential for assistive technology, wearables, password managers, parental controls and legitimate work management.

**Useful controls:** review Android's enabled accessibility services, active device administrators, notification listeners and VPN settings; inspect unfamiliar entries through Android's app-info screen. Consider the safety implications before changing anything on a shared or managed device.

**PrivaCage coverage:** existing Monitoring Access Review reads the settings Android exposes, reports missing data as unavailable, and opens Android-owned settings/app-info pages.

**Boundary:** a listed service is not a stalkerware diagnosis; a component name does not establish intent, hidden behavior or what information it actually read. Absence from these four lists does not establish that monitoring is absent. No app inventory or notification contents are read by this review.

### R06 — Sideloading and potentially harmful apps

**Threat:** installing an app from an untrusted source increases the chance of malicious, repackaged or deceptive software. Android's per-source install approval is intentionally scoped to the calling package, not a universal third-party inventory.

**Useful controls:** prefer trusted distribution sources, inspect the developer and signing continuity, review requested permissions, and keep Google Play Protect scanning enabled where Google Play Services are present. Google says Play Protect checks Play Store apps, scans potentially harmful apps from other sources, warns users and may disable/remove harmful apps.

**PrivaCage coverage:** the existing user-selected APK audit checks manifest declarations, exported components, signer metadata/signature integrity and bounded tracker strings without installing or uploading the APK. The checklist provides a manual Play Protect review.

**Boundary:** Play Protect is a Google service, not an offline PrivaCage detector. Google documents that it may receive device network connections, potentially harmful URLs and OS/app details; sending an unknown app for enhanced analysis has a separate data-sharing implication. The user must review those choices. PackageManager.canRequestPackageInstalls() applies only to the calling package when the relevant install permission is declared; it cannot enumerate all apps permitted to request installs.

### R07 — Overlay abuse and tapjacking

**Threat:** an overlay or partially obscured control can mislead a user into tapping an unintended security-sensitive button. Android has mitigations for some full-occlusion cases, but partial occlusion and activity-sandwich patterns remain relevant.

**User action:** review apps with “display over other apps” access; be cautious about unexpected overlays and prompts; close suspicious screens instead of approving an action through an obscured interface.

**PrivaCage coverage:** research and a future candidate for an explicit overlay-access review.

**Boundary:** there is no safe public API for an ordinary app to produce a complete, reliable global inventory of every overlay permission and prove whether an app is currently maliciously obscuring another screen. An app can harden its own sensitive UI against obscured touches; that is not a global malware detector.

### R08 — USB debugging and trusted-computer authorizations

**Threat:** an unattended device with debugging enabled and an already-authorized computer can expose a powerful development interface. An unexpected authorization prompt should not be approved.

**User action:** keep USB debugging off when it is not actively needed; review and revoke authorizations for computers no longer trusted; do not approve unfamiliar prompts.

**PrivaCage coverage:** manual checklist and handoff to Developer options.

**Boundary:** Android's public Settings.Global ADB_ENABLED and DEVELOPMENT_SETTINGS_ENABLED values are specified to return 0 for all third-party apps. PrivaCage therefore must not present those readings as evidence that debugging is off.

### R09 — Wi-Fi rogue access points, captive portals and DNS privacy gaps

**Threat:** a local Wi-Fi operator may observe connection metadata and destination IPs; DNS may be visible unless encrypted; captive portals and impostor access points can create misleading trust prompts. HTTPS protects application content in transit but does not hide all connection metadata.

**Useful controls:** avoid treating a familiar SSID as proof of network identity; use strict, validated Private DNS where appropriate; keep HTTPS and app updates; review VPN ownership and coverage.

**PrivaCage coverage:** the device snapshot reports selected network/Private DNS/VPN settings; the DNS engine can filter supported UDP DNS directed to its virtual endpoints and optionally use strict DNS-over-TLS for PrivaCage's upstream.

**Boundary:** this is not a general packet firewall. App-owned DoH/DoQ, direct-IP connections, DNS-over-TCP initiated by clients, arbitrary tunnels and general IPv6 traffic may bypass the DNS policy. A VPN provider becomes a trust point; a VPN indicator does not prove all traffic is routed through it.

### R10 — Bluetooth, NFC and nearby-radio attack surface

**Threat:** wireless stacks and connected accessories add attack surface; vulnerabilities can exist in Android, chipset, accessory firmware or vendor components. The November 2026 Android bulletin includes critical Bluetooth kernel issues for the later November patch level.

**User action:** install system and accessory updates; remove pairings that are no longer trusted; keep discoverability and nearby permissions limited to what is needed; disable radios/features that the user is not using where convenient.

**PrivaCage coverage:** documentation and future user-guided permission/radio review only.

**Boundary:** Bluetooth/NFC radio state alone is not a malware signal. A stock app cannot certify accessory firmware or inspect all modem/controller firmware. Do not label an enabled radio as an attack.

### R11 — Notification, clipboard and lock-screen data exposure

**Threat:** private message previews, one-time codes, clipboard content and notification mirrors can reveal information to people or applications that can view them.

**User action:** hide sensitive lock-screen notification content; review notification-listener access; avoid copying secrets into shared clipboards; use app-specific protections for password/OTP content.

**PrivaCage coverage:** Monitoring Access Review checks the notification-listener component setting where the platform exposes it, without reading notification text. PrivaCage itself uses user-selected clipboard copy operations for drafts/exports and does not continuously monitor the clipboard.

**Boundary:** Android's clipboard protections differ by version and apps. A third-party app does not receive a universal history of another app's clipboard operations. Notification-listener access is a capability, not proof that messages were read.

### R12 — Exported components, unsafe intent handling and WebView bridges

**Threat:** an app that unintentionally exports activities, services, receivers or providers can expose internal actions/data. Intent redirection can make a vulnerable app launch an attacker-controlled component. An unsafe JavaScript/native bridge or local-file-enabled WebView can turn hostile page content into access to app capabilities.

**PrivaCage coverage:** the APK audit reports parsed exported components; source/manifest CI checks can be added to PrivaCage's own build. The user-selected APK scan does not execute the target app.

**Boundary:** static findings are indicators, not proof of exploitability. Dynamic behavior, access-control checks, deep links, native libraries, split APKs and vendor-specific code require separate analysis. No arbitrary code is executed by this auditor.

### R13 — Backups, removable storage and account recovery

**Threat:** app data copied to a cloud/device backup, removable volume or synced account can outlive the original device. A lost account recovery channel can also undo local privacy protections.

**User action:** review device backup/sync settings, protect the cloud account with a strong unique credential and multi-factor authentication, and check the actual destination before exporting sensitive reports.

**PrivaCage coverage:** the app declares its own Android backup posture and has a validation gate. Sensitive Android-local stores use Android Keystore AES-GCM; exported signed checkpoints remain plaintext JSON and require user-controlled destination protection.

**Boundary:** an app's allowBackup=false does not govern every OEM transfer, cloud account, screenshot, export destination or other app's backup behavior. No app can verify every provider's retained backup copies.

### R14 — SIM swap and number-port fraud

**Threat:** an attacker who convinces a carrier to transfer a phone number may receive SMS/voice recovery traffic. This is a carrier-account and identity-verification risk, not something an Android app can detect through a radio-generation callback.

**User action:** where the carrier offers them, review account PIN/passphrase and number-port protection; use authenticator or passkey-based sign-in instead of SMS as the only second factor for important accounts.

**PrivaCage coverage:** education only in this build.

**Boundary:** no public Android API tells an ordinary app whether a carrier account has a port-out lock or whether a SIM replacement request is legitimate. Do not infer a SIM-swap incident from loss of signal alone.

### R15 — Device management and shared-device visibility

**Threat:** a work/school administrator, family-management feature or device owner may enforce policies or see some activity. A security review on a managed or shared device can itself be visible to an administrator.

**User action:** understand whether the device is personally owned, managed or shared before changing policy. Do not disable workplace/school management based only on an unfamiliar label.

**PrivaCage coverage:** current-user/profile administrator review is informational, and the UI warns that management entries can be legitimate.

**Boundary:** the ordinary app cannot establish the identity, motives or full administrative scope of the organisation controlling a device. A managed-device owner may have authority beyond the normal-app observation scope.

## 4. Direct signals, user reports and unavailable signals

| Signal | Evidence class | What PrivaCage can say | What it must not claim |
|---|---|---|---|
| Packet-data generation | OS-observed | Android reports GSM 2G / another type / unknown for the default subscription | “A fake cell was detected” or “radio is encrypted” |
| Security patch date | OS-reported | Android exposes this date string | “All firmware and OEM components are current” |
| Secure screen lock | OS-observed | Android reports secure credential configured / not configured | “Credential is strong” or “device is uncompromised” |
| 2G toggle per SIM | User-reported | User says every active SIM was checked | “PrivaCage independently verified all SIM policies” |
| Native unencrypted alerts | User-reported | User says the compatible Android notification setting is enabled | “The modem supports or sent an alert” |
| USB debugging | User-reported / otherwise unavailable | User checked Developer options | “ADB is off” from Settings.Global third-party reads |
| Play Protect | User-reported | User checked the Play Protect scan toggle | “PrivaCage scanned or cleared every installed app” |
| Bootloader / Verified Boot | Unavailable to this build | No result; inspect device boot warning and vendor integrity surface | “Bootloader is locked” from a hidden property |
| Carrier port-out protection | Unavailable to this build | User must check with the carrier | “SIM swap protection is active” |

## 5. Implementation decision and release gates

### Built in this experimental slice

- Encrypted local user-confirmed checklist using Android Keystore AES-GCM.
- Direct Android-reported security patch date.
- Direct KeyguardManager.isDeviceSecure() result.
- Settings handoffs for each checklist item.
- Separate values for not reviewed, user confirmed and unavailable.
- Explicit note that the checklist is not an OS-verified security score.
- Android classifier tests and strict checklist schema tests.

### Existing related capabilities

- Monitoring Access Review: accessibility services, active administrators, notification listeners (best-effort setting source) and default-network VPN transport.
- Permission declaration/grant baseline for launcher-visible apps.
- User-selected APK manifest/signature/exported-component audit and version diff.
- Bounded DNS policy and optional local DNS history.

### Not claimed or not yet built

- No global USB-debugging read, bootloader/Verified Boot attestation, Play Protect status API, all-app sideload inventory, all-SIM cipher inspection, rogue-base-station detection, carrier SIM-swap state, full packet firewall or general sensor/API-call monitor.
- No Accessibility Service is added for this checklist.
- No READ_PHONE_STATE, cell-location, location, QUERY_ALL_PACKAGES, or new runtime permission is requested for this slice.
- No score is computed by turning unavailable signals into a positive result.

### Required device validation

- Android 12–16 devices across OEMs, carriers, eSIM/dual-SIM and Wi-Fi-only variants.
- A device with no secure lock credential and one with a secure credential.
- A range of security-patch strings, including blank/unavailable and vendor-specific update behavior.
- Mobile security settings present and absent, including Android 16 modems with and without IRadio 3.0 support.
- Local checklist storage encryption, corrupted ciphertext, missing Keystore key and explicit user-status changes.
- Shared/managed-device warning review before presenting the onboarding screen.

## 6. Source notes

Official references are catalogued in SOURCES.md under S40. The November 2026 bulletin is current as of 8 November 2026; recheck each monthly bulletin and the device manufacturer's own security releases before publishing a new “current” or “patched” verdict.
