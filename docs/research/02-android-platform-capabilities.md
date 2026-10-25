# 02 — Android Platform Capability Audit

**Research status:** official API review, 25 October 2026  
**Decision this note supports:** design a real stock-device MVP without smuggling privileged features into ordinary code.

## 1. Capability tiers

PrivaCage must label capabilities by the privilege that actually enables them.

| Tier | Examples | Baseline promise |
|---|---|---|
| A — ordinary app APIs | Read its own files/preferences; request declared permissions; open system Settings pages; inspect a user-selected APK/file; collect its own app events | Ship normally, with normal Android permission prompts |
| B — user-authorized VPN | Create a `VpnService` tunnel after system consent; route the configured traffic; read packets presented on its virtual interface; apply local packet/DNS rules | Can observe the routed network layer, not other processes' arbitrary API calls |
| C — constrained cross-app metadata | Query installed packages allowed by package-visibility rules; active VPN may call `ConnectivityManager.getConnectionOwnerUid()` for supported TCP/UDP tuples when permitted | Partial visibility; report unknown/unavailable rather than infer |
| D — privileged, rooted, or system-integrated | Alter other apps' AppOps state beyond allowed authority, hook other processes, inject synthetic sensor/location/clipboard values, inspect vendor system services | Separate optional modules; require device-specific validation, explicit warnings and a documented threat model |
| E — not generally available | Universal observation of all app-level API calls on every stock build; silent permission override; reading another app's private database | Do not claim or emulate as implemented |

## 2. What `VpnService` actually provides

Android's official VPN guide describes a service that creates a virtual network interface and routes selected app traffic. `VpnService.Builder.addAllowedApplication()` and `addDisallowedApplication()` control which apps use the VPN; excluded apps use system networking as if the VPN were not running. The API also supports bypass behavior and requires the implementation to forward/reinject traffic correctly ([S01](SOURCES.md#s01)–[S03](SOURCES.md#s03)).

That is a network-layer interception mechanism. It does **not** provide a stream of Java/Kotlin method calls or syscalls from other apps. Therefore, it cannot by itself prove that an app called `ClipboardManager.getPrimaryClip()`, queried GPS, registered a sensor listener, opened the camera, read contacts, or accessed a photo. The event model must not manufacture those event types from packet activity.

### Attribution

On API 29 and later, `ConnectivityManager.getConnectionOwnerUid(protocol, local, remote)` can identify the UID owning a supported TCP/UDP connection in the supported context of an active VPN service. Its documented failure result includes an invalid UID when the connection cannot be found ([S04](SOURCES.md#s04)). This does not mean every packet can always be mapped to a package. Flows may be short-lived, tuple state may have expired, traffic can be system-owned, and different platform versions/OEM builds may behave differently.

Implementation requirements:

- Add `attribution = VERIFIED_UID | SYSTEM_UID | AMBIGUOUS | UNKNOWN` to the normalized network event.
- Record the API level and attribution method used.
- Map UID to a package only when the package mapping is known and current; handle shared UIDs and multiple packages carefully.
- Never guess the app from a domain's popularity or from the app currently visible in the UI.
- Test TCP and UDP separately, IPv4 and IPv6, foreground/background apps, rapid connections, and VPN revocation.
- If the device/OS does not provide a reliable mapping, show a system-level/unattributed flow rather than a false attribution.

## 3. Package visibility and installed-app inventory

Apps targeting Android 11/API 30 or later have package-visibility filtering. The system exposes some packages automatically; additional package queries can be declared with `<queries>`, and `QUERY_ALL_PACKAGES` is subject to Google Play approval where the app is distributed there ([S05](SOURCES.md#s05)). An installed-app scanner must not assume it can list every package on every API/installer/distribution path.

Recommended design:

1. Prefer the smallest package visibility needed to fulfil a clearly disclosed feature.
2. If broad visibility is truly essential, explain why, request only the approved capability, and degrade gracefully if denied or not granted by store policy.
3. Offer a user-selected APK import path for full local analysis; never send an APK off-device unless the user explicitly selects a remote scanner and sees what leaves the device.
4. Distinguish “not visible to this build” from “not installed.”

## 4. Permissions and AppOps

The ordinary permission workflow is: inspect granted state where public APIs allow; present an explanation; open the relevant system settings screen; then re-read state after the user returns. It is not safe to design a non-root `PermissionToggleService` as if it has universal authority to change another package's AppOps mode. `AppOpsManager` is a framework interface and some cross-package operations are restricted ([S09a](SOURCES.md#s09a)); the user's app's privilege level, SDK surface and Android version determine what is allowed.

Likewise, `PackageManager.setComponentEnabledSetting()` is not a generic substitute for a cross-app permission controller. Its actual authority must be verified for the component/package and target OS. The MVP should not use it to pretend that third-party app permissions were changed.

**Recommended MVP behavior:** show current platform-reported permission/permission-group state where available, identify the exact system settings action, and verify the change after the user returns. If it cannot modify a permission directly, the UI should say “Open Android settings” rather than showing a false successful toggle.

A separate root/system extension can explore AppOps controls only after it checks: Android build fingerprint, available commands/API, SELinux context, rollback support and observed outcome. An attempted command is not proof of a successful permission change.

## 5. Fake or empty data injection

Returning fake GPS coordinates, empty contacts, synthetic clipboard data or dummy sensor values to another unmodified app generally requires cooperation from the OS, root-level instrumentation, a hook/injection framework, or a modified app. A stock companion app cannot reliably interpose on arbitrary process calls. This feature must be marked **root/system-integrated only — not part of the stock MVP** unless a concrete supported mechanism is identified and tested.

Do not silently fake a “permission denied” event. If a privileged shim is later built, its record must distinguish requested operation, actual enforcement mechanism, API result, fallback behavior and app crash/compatibility outcome.

## 6. Clipboard, sensors, photos and location

Modern Android permission behavior is designed to constrain sensitive access. For example, Android 13 added a system visual confirmation when content is copied to the clipboard, and background body-sensor access has a dedicated permission model that changed in Android 13 and later ([S08](SOURCES.md#s08), [S09](SOURCES.md#s09)). Such protections do not create a universal observer API for a separate third-party app.

PrivaCage should use these signals carefully:

- **Permissions:** can indicate access a package may request or has been granted, not proof of use.
- **System privacy indicators/reports:** present only data exposed through documented public APIs or manually shared by the user.
- **Clipboard/sensor/location event log:** do not claim cross-app coverage on stock devices without a verified signal source.
- **Background access:** evaluate each permission under the target Android version; do not treat a manifest declaration as effective permission.
- **Photo access:** prefer Android's user-mediated Photo Picker when PrivaCage only needs selected content for its metadata scrubber.

## 7. VPN conflicts, failure and network safety

A user-authorized VPN can conflict with another VPN, enterprise tunnel or DNS/ad-blocking product. When it is revoked, stopped or cannot establish, the application must accurately communicate what is and is not being filtered. For sensitive blocking, provide a clear choice between a transparent fail-open mode (network continues but no enforcement is guaranteed) and a fail-closed/lockdown option only where the OS supports and the user has intentionally configured it. Never display “protected” when packets are not traversing the enforcement path.

Operational requirements:

- Explicitly ask for VPN consent using Android's own flow.
- Show which apps are included/excluded and whether bypass is possible.
- Add route coverage for IPv4 and IPv6; do not leak IPv6 around an IPv4-only rule set.
- Preserve a recovery path and prevent infinite tunnel recursion with correctly protected upstream sockets.
- Handle `onRevoke`, process death, device reboot and network changes; do not assume the service is always active.
- Explain that a local VPN is not an anonymity service and does not hide traffic from the destination or the internet provider in the same way a remote VPN might.

## 8. Root extension gate

Do not make root support the quiet fallback for stock-device limitations. Gate it behind a separate install, a plain-language warning and a list of exact capabilities the extension adds. Test on known Android versions and ROMs; record failures; no broad “works on rooted Android” claim without a device matrix. A root module increases attack surface and can make the phone less secure if compromised.

## 9. Acceptance criteria

- No code path reports a clipboard/sensor/syscall event from VPN packets alone.
- A flow with no UID attribution remains `UNKNOWN` end-to-end.
- Permission changes initiated through Settings are re-read and verified before the UI reports success.
- App inventory obeys package visibility and documents incomplete visibility.
- Unsupported root-only operations return an explicit capability-unavailable result rather than mock success.
- VPN stopped/revoked states are visible, and no “blocked” claim is emitted without confirming that the matching packet/flow was dropped by an active rule.