# PrivaCage Windows Privacy Baseline Auditor

This is the first Windows implementation milestone: a **read-only local configuration snapshot** for Windows 10/11. It does not install a service, change policy, create firewall rules, inspect packets, or contact a remote service.

## Checks

- **Windows Firewall profiles:** reads the Domain, Private, and Public profile states from the active Windows Firewall policy store, including enabled state and default inbound/outbound actions.
- **Diagnostic-data policy:** reads the machine policy value `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry` when present.
- **Windows App Privacy policy:** reads machine-level `LetAppsAccessLocation`, `LetAppsAccessCamera`, and `LetAppsAccessMicrophone` values when present.

Each finding includes an observed value, an explanation, a suggested review action, and an official Microsoft reference. `not_configured` means the specific machine policy value was not found; it does **not** mean a feature is disabled. `unknown` represents a failed, malformed, or unrecognized read, not a clean bill of health.

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell (`powershell.exe`) and the `NetSecurity` module for firewall-profile inventory.
- Go 1.27 or newer to build from source.

Some managed or restricted systems may deny access to policy values. The tool reports unknown state instead of silently treating a read failure as an absent policy. It does not require elevation by design; a system that restricts inspection may return unknown findings.

## Run on Windows

From this directory:

    go test ./...
    go run . --format text
    go run . --format json > windows-baseline.json

To build an executable:

    go build -o pcage-audit.exe .

The JSON file contains the point-in-time policy findings and their limitations. It does not include usernames, machine names, SSIDs, IP addresses, packet payloads, or app traffic records. Store exports intentionally; a destination folder may be synced by another service.

## Important limitations

- Firewall profile configuration does not show which rules matched a connection, which destinations an app contacted, or whether data was sent.
- The diagnostic-data result is a machine policy value, not an independent measurement of network traffic or the complete effective policy. The meaning of value `0` depends on the Windows edition; value `2` is legacy/OS-dependent.
- The privacy policy keys queried here cover machine-level policy only, not all user preferences, individual-app choices, MDM precedence, traditional desktop programs, services, drivers, or OS components.
- This release does not apply fixes. It makes no registry writes, firewall changes, network requests, or automatic hardening decisions.
