# Platform capability and permission matrix

This matrix describes what PrivaCage can truthfully observe or enforce on stock operating systems. The OS APIs are authoritative for the capabilities they expose; they do not imply unrestricted access to other apps or system services.

## Android

| Area | API / permission surface | Current PrivaCage behavior | Limit that must stay visible |
|---|---|---|---|
| Local DNS filtering | User-approved `VpnService`; virtual interface addresses and specific routes from `VpnService.Builder`; foreground service | Routes only the configured virtual IPv4 and IPv6 DNS endpoints into a local TUN, processes supported UDP DNS packets and protects upstream sockets from routing back into the VPN. | Not a full-device VPN/firewall. It does not accept client-facing DNS-over-TCP, inspect arbitrary HTTPS, decode DoH/DoQ, or prevent direct-IP traffic. IPv6 extension headers/fragments/jumbograms are rejected. |
| Network snapshot | `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, public connectivity APIs | Reports exposed network/VPN/Private DNS/Wi-Fi radio indicators. | Does not read location coordinates or Wi-Fi SSIDs in the privacy snapshot. It cannot infer all OEM/system traffic or prove all app packets use the configured resolver. |
| Installed-app visibility | Manifest `<queries>` with launcher intent; `PackageManager` visible-package APIs | Scans launcher-visible apps for dangerous permission declarations and grant flags. | Android 11+ filters package visibility by default. A launcher query is not a complete inventory of hidden/headless system packages, work profiles, privileged Google/Samsung services or every installed package. No `QUERY_ALL_PACKAGES` claim is made. |
| Permission inventory | `PackageInfo.requestedPermissions`, `requestedPermissionsFlags`, permission protection levels | Reports dangerous permissions declared by visible apps and the exposed grant state; compares complete scans against a local baseline. | A manifest declaration is not live sensor use. A granted flag is not proof the app used the permission, collected data, or transmitted it. Package disappearance is not treated as permission revocation. |
| APK static audit | User-selected APK URI, Android package archive parsing, APK signature verification and bounded DEX string scanning | Reports package/version/target SDK, declared permissions, exported components, SHA-256, signer certificate fingerprints, signature-integrity result and possible tracker indicators. | Does not install or execute the APK. Valid signature integrity is not proof of publisher identity or safety; DEX strings are not runtime evidence. Obfuscation, native code, reflection and runtime downloads can evade static indicators. |
| Local app alternatives | Bundled reviewed JSON, HTTPS allowlist, Android `ACTION_VIEW` source handoff | Saves selected replacements and source preferences locally, opens one selected store/project page at a time, and lets the user track completion. | Current entries are landing pages, not pinned binary artifacts. PrivaCage does not silently sideload APKs or infer install success from opening an external page. |
| Package installation | Android PackageInstaller / system installation intent | The alternative picker lets the selected store or project source run its normal flow. | Any future direct-APK workflow must verify a pinned artifact digest and signing identity, bound downloads, report the source and package details, and hand off to Android's user-confirmation flow. It must not bypass Play Protect or install-confirmation safeguards. |
| Encrypted profile transfer | Storage Access Framework; Argon2id + AES-256-GCM envelope | Exports and imports an encrypted `.pcage` configuration file only after local validation. | Does not encrypt live DNS traffic by itself, authenticate the sender, or provide key recovery. |
| Privacy controls | Links to official Android/Google/Samsung settings pages | Helps the user open settings that they can review themselves. | Opening a settings page is not an opt-out and does not prove the setting changed. No privileged system toggle is implied. |

### Android source references

- [VpnService](https://developer.android.com/reference/android/net/VpnService) — user-authorized VPN service lifecycle and socket protection.
- [VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder) — virtual interface addresses, DNS server entries, routing and MTU.
- [Declare package visibility needs](https://developer.android.com/training/package-visibility/declaring) — Android 11+ package visibility and `<queries>` scope.
- [PackageInfo](https://developer.android.com/reference/android/content/pm/PackageInfo) — exposed package manifest metadata and requested permission flags.
- [PackageInstaller](https://developer.android.com/reference/android/content/pm/PackageInstaller) — installation statuses, including cases where user action is required.
- [Android VPN guide](https://developer.android.com/develop/connectivity/vpn) — platform VPN setup and behavior.

## Windows

| Area | API / policy surface | Current PrivaCage behavior | Limit that must stay visible |
|---|---|---|---|
| Firewall baseline | Windows PowerShell `Get-NetFirewallProfile -PolicyStore ActiveStore` | Reads Domain, Private and Public profile enablement and default inbound/outbound actions. | Does not capture which rule matched a packet, inspect payloads, or prove a connection succeeded. A profile summary is not full egress telemetry. |
| DNS resolver inventory | Windows PowerShell `Get-DnsClientServerAddress` | Lists configured resolver addresses by interface and address family in a local report. | Does not determine which resolver served a particular app query, whether DNS is encrypted, or whether an app uses DoH/DoQ, a VPN or its own resolver. Resolver addresses can reveal local network details, so reports should be kept private. |
| Current-user proxy state | WinINET current-user proxy registry flags | Reports whether the current-user WinINET proxy toggle, proxy-server setting and auto-configuration URL are present; omits endpoint strings from the report. | Does not inspect all WinHTTP, VPN, enterprise, browser-specific or per-app proxy behavior and does not authenticate or validate the proxy operator. |
| Diagnostic-data policy | Machine `AllowTelemetry` policy value | Shows the configured machine-level policy as one piece of the local privacy baseline. | Does not measure actual network traffic or cover additional organization-installed apps. Microsoft's documented “Diagnostic data off” value is restricted to supported Enterprise, Education and Server editions; other client editions use different supported levels. |
| Windows-app permissions | Windows App Privacy policy values such as `LetAppsAccessCamera`, `LetAppsAccessLocation`, `LetAppsAccessMicrophone` | Read-only audit reports selected policy values; the strict hardening profile can set its documented allowlisted Windows-app capability policies with confirmation and rollback. | This is not a universal barrier for every classic desktop program, service, driver, OS component or firmware route. Windows apps may need a restart for a policy change to apply. |
| Policy changes | Allowlisted registry DWORD policies; protected prior-state backup; UAC; verification and restore | Requires an explicit preview/confirmation before apply; stores prior values and verifies observed state after writing. | MDM/domain policy can override local values. A successful local registry write does not prove that the effective policy changed or that data stopped flowing. Restore depends on the saved backup and available services. |
| Network isolation | Windows Defender Firewall profile defaults and a named outbound block rule | Provides separate, explicit high-impact outbound controls with warnings and recovery guidance. | Can break DNS, downloads, updates, cloud tools and remote administration. Does not prove silence at kernel, driver, firmware, hypervisor, hardware-management, external-router or out-of-band layers. |

### Windows source references

- [System Policy CSP — AllowTelemetry](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system) — describes diagnostic-data policy and supported edition boundaries.
- [Privacy Policy CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy) — defines Windows-app capability policies and their scope.
- [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile) — profile state collection.
- [Get-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress) — adapter DNS configuration inventory.
- [Setting and Retrieving Internet Options](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options) — WinINET option scope and per-connection behavior.
- [Enabling Internet Functionality](https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality) — documents the WinINET `ProxyEnable` / `ProxyServer` setting semantics.

## iOS

| Area | Public platform capability | PrivaCage scope | Limit that must stay visible |
|---|---|---|---|
| Network filtering | NetworkExtension capabilities such as approved VPN/DNS-related providers, subject to Apple entitlement and distribution rules | Planned only; no release claim in the current branch. | An ordinary iOS app cannot inventory another app's executable, inspect arbitrary app-private files, or override app permissions. Any NetworkExtension design needs explicit entitlement/distribution verification and device tests. |
| Privacy settings | User-visible Settings and public APIs available to the app itself | Future user-guided controls only. | An app cannot silently flip arbitrary system privacy switches or reliably observe all cross-app sensor/collection behavior. |

## Engineering rule

When an API gives a partial inventory, report the inventory's scope in the same UI as the result. Distinguish **not configured**, **not visible**, **read failed**, **not supported**, and **observed but not enforced**. Never translate “not observed” into “does not happen,” and never label a policy write as enforced without readback and platform-level validation.
