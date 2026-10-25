# Windows Privacy Hardening Research — 25 October 2026

## Executive summary

Windows exposes supported policy controls that reduce selected diagnostics, ad-ID use, Activity Feed sharing, tailored experiences, online speech personalization, and some Windows-app capability access. A local administrator can configure documented policies, but administrative rights do not grant control over every OS component, driver, firmware layer, remote-management policy, or network route.

The implementation therefore follows a limited claim: **apply documented local policy choices, verify the values Windows currently reports, and let the user restore the prior state.** It does not promise that Windows sends no data, and it deliberately preserves Windows Update, Defender, SmartScreen, licensing, and certificate validation.

## Threat areas and supported controls

### 1. Windows diagnostic data

Microsoft's System Policy CSP documents AllowTelemetry with value 1 for Required diagnostic data and 3 for Optional diagnostic data. Value 0 ("Security") is supported only on specific Enterprise, Education, IoT, and Server editions; on other editions, Microsoft documents that value 0 behaves like value 1. Required diagnostics still include data used to keep Windows secure, up to date, and operating as expected.

**PrivaCage behavior**
- On commonly used Professional editions, balanced and strict profiles set AllowTelemetry=1, the lowest documented level for the supported policy.
- On editions Microsoft documents as supporting Security-only diagnostics, the profiles use value 0.
- On Windows Home/Core, the machine-policy controls are skipped rather than being presented as enforced.
- On supported Windows 11 builds, the plan also applies LimitDiagnosticLogCollection=1 and LimitDumpCollection=1 to constrain additional diagnostic logs/dumps.

**Limit:** this does not establish zero traffic. Optional diagnostic data can include diagnostic logs and crash dumps; required diagnostic data remains a separate minimum. Policy meaning varies by Windows edition and build.

Sources:
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system
- https://learn.microsoft.com/en-us/windows/privacy/optional-diagnostic-data
- https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization

### 2. Advertising identifier

Microsoft's Windows privacy guidance documents an advertising identifier setting and a machine policy mapping under Software\Policies\Microsoft\Windows\AdvertisingInfo (DisabledByGroupPolicy). The client user preference is also stored under the current user's Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo path.

**PrivaCage behavior**
- Set the current interactive user's documented advertising-ID preference to disabled where that user hive is available.
- Where machine policy is supported, set DisabledByGroupPolicy=1.
- Do not imply that this removes previously collected data or all advertising measurement.

Source: https://learn.microsoft.com/en-us/windows/privacy/windows-privacy-compliance-guide

### 3. Activity Feed and cloud activity sharing

Microsoft's Privacy Policy CSP maps Activity Feed and User Activities settings to the machine System policy key. EnableActivityFeed=0 disables Activity Feed publication/cloud roaming; PublishUserActivities=0 stops publication; UploadUserActivities=0 disables uploading. The last two are build-gated because their documented availability differs.

**PrivaCage behavior**
- Use these values only on supported builds.
- Report skipped controls for earlier builds rather than assuming the registry values are honored.

Source: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy

### 4. Tailored experiences and online speech personalization

Microsoft's Experience CSP documents the per-user DisableTailoredExperiencesWithDiagnosticData policy for preventing diagnostic data from being used to customize lock-screen content, tips, and related consumer experiences. The Privacy CSP documents AllowInputPersonalization for online speech-recognition/personalization behavior.

**PrivaCage behavior**
- Disable tailored experiences for the active interactive user where that user hive is loaded.
- Set AllowInputPersonalization=0 on supported machine-policy editions.
- Do not claim this disables every local typing, inking, speech, assistant, or application-specific history feature.

Sources:
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience
- https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy

### 5. Windows-app capability access

The Privacy Policy CSP documents force-deny values for Windows-app capabilities such as location, camera, microphone, contacts, calendar, email, messaging, call history, tasks, notifications, and access to diagnostic information about other apps. The value 2 represents "Force deny" for the documented Windows-app scope.

**PrivaCage behavior**
- The strict profile adds value 2 for the listed capabilities where the OS build supports the relevant policy.
- The app labels these as Windows-app restrictions, not universal barriers against every traditional desktop application, service, driver, or OS component.
- Applying the profile can break apps that rely on those capabilities.

Source: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy

### 6. Windows Error Reporting

Microsoft documents the Windows Error Reporting policy Disabled=1 under Software\Policies\Microsoft\Windows\Windows Error Reporting.

**PrivaCage behavior**
- Included only in the strict profile because it removes a crash-reporting/troubleshooting path.
- This controls Windows Error Reporting policy, not every diagnostic or service communication.

Source: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-errorreporting

### 7. Network egress controls

Windows Firewall supports configured default inbound/outbound profile actions and explicit rules. Default outbound Block is not identical to a universal deny: explicit allow rules may still permit connections. An explicit all-program outbound block rule is more disruptive but can still not establish that every privileged, kernel, driver, firmware, hypervisor, remote-managed, or external-network path is covered.

**PrivaCage behavior**
- The --block-outbound-by-default flag changes all three profile default outbound actions to Block; it preserves other rules.
- The --isolate-network flag adds a named, identifiable outbound block rule for all programs and enables the firewall profiles.
- Both require --confirm-network-disruption at preview and apply time. The interactive console requires the exact phrase ISOLATE NETWORK.
- Before changing firewall state, PrivaCage stores original profile Enabled and DefaultOutboundAction values in its protected backup. Restore removes only the identifiable PrivaCage rule and restores captured profile settings.
- Restore checks the observed state before reporting success. If restoration fails, the backup remains.

**User-impact warning:** either mode can interrupt DNS, browser traffic, downloads, Windows Update, security-signature updates, cloud access, remote administration, and application networking. Do not enable isolation when relying on remote access to restore it. Keep physical/local console access available.

Source: https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line

## Why PrivaCage does not block hardcoded Microsoft IP ranges or rewrite hosts

Microsoft documents multiple service endpoints and TLS/certificate pinning for diagnostic transfers. Endpoint inventories change, addresses may be shared, and the same services support security, updates, certificates, licensing, and reliability. A hosts-file rewrite or static IP denylist is brittle and can break system integrity checks without proving that a data channel has been stopped.

Source: https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization

## Transaction and trust design

- Preview (plan) makes no policy changes.
- Apply is an explicit command requiring --confirm; any network-disruption flag requires a second explicit acknowledgement.
- Mutating commands request UAC elevation.
- Registry writes are restricted to an in-code allowlist and documented DWORD settings. Existing non-DWORD values cause a fail-closed error rather than an overwrite.
- Before changes, a backup is saved under %ProgramData%\PrivaCage\hardening-backup.json, with directory access restricted to SYSTEM and Administrators.
- A second active profile cannot overwrite the saved state. Restore replays prior values, removes values that were previously absent, restores captured firewall profile state, and verifies the restored state before removing the backup.
- Failed applies attempt rollback. If rollback is incomplete, the backup remains and the error identifies the recovery path.
- Windows policy or MDM can later override local values; verification is a point-in-time readback, not a guarantee of durable effective policy.

## Explicit non-goals and limitations

PrivaCage does not attempt to disable Windows Update, Defender, SmartScreen, certificate revocation, licensing, or essential security components. It cannot guarantee that Windows sends no data. It cannot audit or control every kernel/driver/firmware communication, hypervisor channel, hardware management engine, OEM service, network appliance, cellular/firmware path, or remote policy administrator. An enabled local firewall is not proof that all egress routes are covered. Machine policy values are not a complete calculation of user policy, MDM precedence, per-app choices, or effective state.

This milestone is a local policy-hardening controller, not a signed Windows service, kernel filter, packet capture engine, enterprise MDM client, or complete connection monitor. Those future capabilities require separate design and validation rather than being implied by an administrator token.
