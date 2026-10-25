# PrivaCage Windows Privacy Control

A local-first Go CLI and monochrome interactive console for Windows 10/11. It inspects supported local settings and applies only a narrow allowlist of documented policy values. Policy changes require explicit confirmation, UAC elevation, a protected rollback backup, and post-write verification.

## Monochrome design

The terminal UI follows the PrivaCage design language: near-black background, white emphasis, neutral-grey dividers/secondary copy, Braille mark, compact labels, and restrained separators. It uses no animated decoration, honors NO_COLOR and TERM=dumb, and remains keyboard-driven.

## Profiles

### Balanced

Previews and can apply edition/build-supported controls:
- Set AllowTelemetry to Required (value 1) on mainstream Professional editions, or Diagnostic data off (value 0) on Enterprise, Education, and Server editions that support it. This governs Windows diagnostic data, not every system communication.
- Disable the active interactive user's advertising-ID preference and, where supported, the machine advertising-ID policy.
- Prevent users from changing diagnostic-data selection in Settings on supported client builds with ConfigureTelemetryOptInSettingsUx=1; administrators and higher-priority policy can still change it.
- Disable Activity Feed publication/cloud roaming, User Activities publication/upload, cross-device clipboard sync, and inclusion of the device name in diagnostic data on supported client builds.
- Disable the documented online speech-recognition/personalization policy.
- Disable tailored experiences based on diagnostic data for the active interactive user when that user hive is available.
- On supported Windows 11 and Windows Server 2022 builds, limit additional diagnostic-log collection and diagnostic dump collection.

### Strict

Includes the balanced profile plus disables Windows clipboard history and adds documented Windows-app permission policy denials for location, camera, microphone, contacts, calendar, email, messaging, call history, tasks, notifications, and diagnostic information about other apps. It also disables Windows Error Reporting policy.

These policies have a narrower scope than the whole machine. They do not create a universal barrier for every classic desktop program, service, driver, OS component, firmware path, or remote administrator. Applications that use denied Windows-app capabilities or Windows Error Reporting can lose functionality.

## Commands

Requires Windows 10/11, Windows PowerShell (powershell.exe), Go 1.27 or newer to build, and the NetSecurity module when firewall state or controls are used.

From this directory:

    go test ./...
    go run . audit --format text
    go run . audit --format json

The read-only audit includes nine bounded checks: the Domain/Private/Public firewall profile state, the machine diagnostic-data policy, Windows App Privacy policies for location/camera/microphone, configured adapter DNS resolver addresses, and the current user's WinINET proxy flags.

DNS resolver addresses are included in the local report as an inventory. That is a potentially sensitive detail about the local network, so keep exported reports private. The audit cannot determine whether a specific request used encrypted DNS, which resolver wins for a given query, whether an application bypasses system DNS, or whether a VPN/enterprise policy changes the effective path. The proxy check reports whether the current-user WinINET toggle and server/PAC settings are present, but does not print the proxy hostname or PAC URL. It does not cover WinHTTP or per-application proxy behavior.

    go run . plan --profile balanced
    go run . plan --profile strict
    go run . apply --profile balanced --confirm
    go run . verify
    go run . restore --confirm-restore

Run go run . in an interactive terminal to open the monochrome console.

Apply and restore request UAC elevation when the current process is not an administrator. Applying requires --confirm. A second profile cannot overwrite a pending backup; restore the active profile first.

## Full Windows customization toolkit

The broader Windows customization workflow is provided by the pinned, MIT-licensed [Win11Debloat](`https://github.com/Raphire/Win11Debloat`) component at `windows/Win11Debloat/`. It is deliberately kept separate from PrivaCage's narrower policy allowlist: Win11Debloat includes app removal, registry and UI changes, optional Windows feature controls, CLI presets, import/export, localization, and its own restore/backup workflow.

Initialize the submodule after a regular clone:

```powershell
git submodule update --init --recursive
```

Launch its GUI from this module directory:

```powershell
go run . debloat
```

The PrivaCage interactive console also offers **10 — Open Win11Debloat customization GUI**. Optional upstream command-line parameters can be forwarded, for example `go run . debloat -CLI`; consult the upstream README/wiki for the full parameter list.

This launch command does not select a preset or modify settings on its own. Win11Debloat's features can remove apps and change Windows settings, services, registry values, shell behavior, and optional features. Review the selected changes before applying them, use its restore-point/backup options where appropriate, and do not assume every tweak is reversible on every Windows build. The separate PrivaCage `apply/verify/restore` transaction remains limited to the policies documented above; it does not wrap or automatically roll back every Win11Debloat operation.

Win11Debloat retains its own upstream interface and license. Its current source is pinned by the Git submodule commit so builds do not silently drift to an unreviewed upstream change.

## High-impact network options

Network changes are separate from the balanced/strict privacy profiles and require additional acknowledgement.

Set all three firewall profiles' default outbound action to Block:

    go run . plan --profile balanced --block-outbound-by-default --confirm-network-disruption
    go run . apply --profile balanced --block-outbound-by-default --confirm --confirm-network-disruption

This is not a universal block: explicit allow rules can continue to permit selected traffic.

Emergency network isolation adds a named outbound block rule for all programs and enables the Domain, Private, and Public firewall profiles:

    go run . plan --profile balanced --isolate-network --confirm-network-disruption
    go run . apply --profile balanced --isolate-network --confirm --confirm-network-disruption

This can immediately break DNS, internet access, downloads, Windows Update, cloud services, remote administration, and network-dependent apps. Use it only when a physical/local console is available and the user understands how to run restore. It cannot prove that kernel, driver, firmware, hypervisor, separate-device, externally managed, or out-of-band traffic is silent.

## Backup and recovery

Before changing settings, PrivaCage saves the previous registry values, whether those values and keys existed, their prior DWORD values, and the three firewall profile states when a network option is requested. The backup path is:

    %ProgramData%\PrivaCage\hardening-backup.json

The containing directory's access control list is restricted to SYSTEM and Administrators. The backup is not encrypted; administrator-level operators can read it. Do not delete it until restore has completed and reported that the captured state was verified.

If an apply fails, the tool attempts rollback. If rollback cannot be completed, it keeps the backup and reports the recovery path. Restore will not delete an altered emergency rule whose description no longer matches PrivaCage's marker.

## What the tool verifies

- Before writes, each allowed registry target is read and its existence and type captured. An existing non-DWORD value is rejected rather than overwritten.
- After applying, policy values are read back and compared with the requested values.
- Firewall profile settings and the emergency rule are checked after the relevant network operation.
- Restore writes captured state back, checks registry and firewall state, and removes the backup only after verification succeeds.
- Failed/unknown verification is not treated as a clean result.

## Limits and safety

- Required diagnostic data remains on ordinary client editions. The Diagnostic data off value (0) is only supported by Enterprise, Education, and Server editions in Microsoft's current policy documentation; IoT Enterprise and mainstream client editions use Required instead. No policy here means "Windows sends zero data".
- Domain policy or MDM can later override local settings. A readback is a point-in-time check, not a complete effective-policy calculation.
- Capability policies cover the Windows-app scope described by Microsoft and do not govern every classic desktop app, service, driver, or OS component.
- Windows Update, Defender, SmartScreen, licensing, certificate validation, and essential security services are deliberately not disabled.
- The tool makes no network requests and does not upload audit or hardening results. It does not install a service, driver, kernel filter, or packet capture engine. DNS resolver addresses are written to the local report; proxy endpoint/PAC URL values are deliberately omitted.
- No hardcoded telemetry IP blocklist or hosts-file rewrite is used. Microsoft endpoint lists evolve, can be shared with essential services, and some diagnostic transfers use TLS/certificate pinning.
- Administrator rights do not override the kernel, firmware, OEM services, hardware management engines, external firewalls/routers, a remote MDM/domain administrator, or all network paths. PrivaCage is a privacy-hardening aid, not proof of absolute non-communication.

Read the sourced analysis in docs/research-notes/windows-privacy-hardening-2026-10-25.md before applying a profile.
