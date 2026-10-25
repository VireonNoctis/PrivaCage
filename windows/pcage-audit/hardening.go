package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

type windowsMetadata struct {
	EditionID          string "json:\"edition_id\""
	BuildNumber        int    "json:\"build_number\""
	InteractiveUserSID string "json:\"interactive_user_sid\""
}

type policyChange struct {
	Hive        string "json:\"hive\""
	SubKey      string "json:\"sub_key\""
	Name        string "json:\"name\""
	Value       int    "json:\"value\""
	Description string "json:\"description\""
	SourceURL   string "json:\"source_url\""
}

type hardeningPlan struct {
	SchemaVersion          int            "json:\"schema_version\""
	Profile                string         "json:\"profile\""
	EditionID              string         "json:\"edition_id\""
	BuildNumber            int            "json:\"build_number\""
	Changes                []policyChange "json:\"changes\""
	Skipped                []string       "json:\"skipped\""
	Warnings               []string       "json:\"warnings\""
	BlockOutboundByDefault bool           "json:\"block_outbound_by_default\""
	IsolateOutbound        bool           "json:\"isolate_outbound\""
}

type policySnapshot struct {
	Hive         string "json:\"hive\""
	SubKey       string "json:\"sub_key\""
	Name         string "json:\"name\""
	KeyExisted   bool   "json:\"key_existed\""
	ValueExisted bool   "json:\"value_existed\""
	ValueKind    string "json:\"value_kind\""
	OldValue     int    "json:\"old_value\""
	TargetValue  int    "json:\"target_value\""
}

type firewallSnapshot struct {
	Name                  string "json:\"name\""
	Enabled               bool   "json:\"enabled\""
	DefaultOutboundAction string "json:\"default_outbound_action\""
}

type hardeningResult struct {
	SchemaVersion    int      "json:\"schema_version\""
	Action           string   "json:\"action\""
	Profile          string   "json:\"profile,omitempty\""
	Success          bool     "json:\"success\""
	Verified         bool     "json:\"verified\""
	AppliedPolicies  int      "json:\"applied_policies,omitempty\""
	VerifiedPolicies int      "json:\"verified_policies,omitempty\""
	Skipped          []string "json:\"skipped,omitempty\""
	Warnings         []string "json:\"warnings,omitempty\""
	BackupPath       string   "json:\"backup_path,omitempty\""
	NetworkAction    string   "json:\"network_action,omitempty\""
	Errors           []string "json:\"errors,omitempty\""
}

type verificationCheck struct {
	ID       string "json:\"id\""
	Expected string "json:\"expected\""
	Observed string "json:\"observed\""
	Status   string "json:\"status\""
}

type hardeningVerification struct {
	SchemaVersion int                 "json:\"schema_version\""
	Action        string              "json:\"action\""
	Profile       string              "json:\"profile\""
	Success       bool                "json:\"success\""
	Checks        []verificationCheck "json:\"checks\""
	Warnings      []string            "json:\"warnings\""
}

const (
	hardeningBackupPath = "PrivaCage\\hardening-backup.json"
	emergencyFirewallRuleName = "PrivaCage.EmergencyOutboundIsolation"
	securityPolicyCSP = "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system"
	privacyPolicyCSP = "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy"
	experiencePolicyCSP = "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience"
	errorReportingPolicyCSP = "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-errorreporting"
)

func buildHardeningPlan(profile string, metadata windowsMetadata, blockOutboundByDefault, isolateOutbound bool) (hardeningPlan, error) {
	if profile != "balanced" && profile != "strict" {
		return hardeningPlan{}, errors.New("profile must be balanced or strict")
	}
	if blockOutboundByDefault && isolateOutbound {
		return hardeningPlan{}, errors.New("choose either --block-outbound-by-default or --isolate-network, not both")
	}
	if metadata.EditionID == "" || metadata.BuildNumber < 10240 {
		return hardeningPlan{}, errors.New("unsupported or missing Windows edition/build metadata")
	}
	plan := hardeningPlan{
		SchemaVersion: 1,
		Profile: profile,
		EditionID: metadata.EditionID,
		BuildNumber: metadata.BuildNumber,
		Changes: make([]policyChange, 0, 24),
		Skipped: make([]string, 0, 4),
		Warnings: make([]string, 0, 6),
		BlockOutboundByDefault: blockOutboundByDefault,
		IsolateOutbound: isolateOutbound,
	}
	add := func(hive, subKey, name string, value int, description, source string) {
		plan.Changes = append(plan.Changes, policyChange{
			Hive: hive, SubKey: subKey, Name: name, Value: value,
			Description: description, SourceURL: source,
		})
	}

	// A user-hive preference scopes to the currently logged-in user's SID.
	if metadata.InteractiveUserSID != "" {
		add("Users", metadata.InteractiveUserSID+"\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", "Enabled", 0,
			"Disable the advertising identifier preference for the active user. This does not erase previously collected profiles.",
			"https://learn.microsoft.com/en-us/windows/privacy/windows-privacy-compliance-guide")
	}
	if !supportsMachinePolicy(metadata.EditionID) {
		plan.Skipped = append(plan.Skipped,
			"Machine Group Policy controls are not documented for this Windows Home edition. The user-level advertising-ID preference may still be applied; unsupported registry policies are not represented as effective.")
	} else {
		telemetryLevel := 1
		telemetryDescription := "Use Required diagnostic data, the lowest documented level on mainstream Pro editions. Required diagnostic data is not zero diagnostic traffic."
		if supportsSecurityOnlyTelemetry(metadata.EditionID) {
			telemetryLevel = 0
			telemetryDescription = "Use the Security diagnostic-data level on an edition where Microsoft documents support for it. This does not promise zero Windows communications."
		}
		add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "AllowTelemetry", telemetryLevel, telemetryDescription, securityPolicyCSP)
		add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo", "DisabledByGroupPolicy", 1,
			"Disable the Windows advertising identifier through the documented machine policy.", privacyPolicyCSP)
		add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "EnableActivityFeed", 0,
			"Disable Windows Activity Feed publication and cloud roaming.", privacyPolicyCSP)
		if metadata.BuildNumber >= 16299 {
			add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "PublishUserActivities", 0,
				"Prevent Windows apps and the OS from publishing User Activities.", privacyPolicyCSP)
		} else {
			plan.Skipped = append(plan.Skipped, "PublishUserActivities requires Windows build 16299 or newer.")
		}
		if metadata.BuildNumber >= 17134 {
			add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "UploadUserActivities", 0,
				"Prevent published User Activities from being uploaded to Microsoft cloud services.", privacyPolicyCSP)
		} else {
			plan.Skipped = append(plan.Skipped, "UploadUserActivities requires Windows build 17134 or newer.")
		}
		add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\InputPersonalization", "AllowInputPersonalization", 0,
			"Disable the documented online speech-recognition/personalization policy.", privacyPolicyCSP)
		if metadata.InteractiveUserSID != "" && metadata.BuildNumber >= 15063 {
			add("Users", metadata.InteractiveUserSID+"\\Software\\Policies\\Microsoft\\Windows\\CloudContent", "DisableTailoredExperiencesWithDiagnosticData", 1,
				"Stop diagnostic data being used for tailored lock-screen, tips, and consumer-feature experiences for the active user.", experiencePolicyCSP)
		} else if metadata.InteractiveUserSID == "" {
			plan.Skipped = append(plan.Skipped, "The tailored-experiences policy was skipped because Windows did not identify an active interactive user hive.")
		} else {
			plan.Skipped = append(plan.Skipped, "The tailored-experiences policy requires Windows build 15063 or newer.")
		}
		if metadata.BuildNumber >= 22000 {
			add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "LimitDiagnosticLogCollection", 1,
				"Limit additional diagnostic-log collection on supported Windows 11 builds.", securityPolicyCSP)
			add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "LimitDumpCollection", 1,
				"Limit dump collection to the documented mini/triage scope on supported Windows 11 builds.", securityPolicyCSP)
		} else {
			plan.Skipped = append(plan.Skipped, "LimitDiagnosticLogCollection and LimitDumpCollection are documented for Windows 11 builds 22000 and later.")
		}

		if profile == "strict" {
			appPrivacy := "SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy"
			for _, item := range []struct {
				name string
				description string
			}{
				{"LetAppsAccessLocation", "Force-deny Windows-app location access; classic desktop apps and system components may be outside this policy scope."},
				{"LetAppsAccessCamera", "Force-deny camera access in the Windows-app permission scope."},
				{"LetAppsAccessMicrophone", "Force-deny microphone access in the Windows-app permission scope."},
				{"LetAppsAccessContacts", "Force-deny Windows-app contacts access."},
				{"LetAppsAccessCalendar", "Force-deny Windows-app calendar access."},
				{"LetAppsAccessEmail", "Force-deny Windows-app email access."},
				{"LetAppsAccessMessaging", "Force-deny Windows-app messaging access."},
				{"LetAppsAccessCallHistory", "Force-deny Windows-app call-history access."},
				{"LetAppsAccessTasks", "Force-deny Windows-app tasks access."},
				{"LetAppsAccessNotifications", "Force-deny Windows-app notification access."},
				{"LetAppsGetDiagnosticInfo", "Force-deny Windows apps from reading diagnostic information about other apps."},
			} {
				add("LocalMachine", appPrivacy, item.name, 2, item.description, privacyPolicyCSP)
			}
			add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting", "Disabled", 1,
				"Disable Windows Error Reporting submission policy. This removes a troubleshooting path and does not stop every diagnostic channel.", errorReportingPolicyCSP)
		}
	}
	if blockOutboundByDefault {
		plan.Warnings = append(plan.Warnings,
			"Outbound defaults will be Block for all three firewall profiles. Explicit allow rules may still permit connections; apps, downloads, cloud functions, and updates can stop working.")
	}
	if isolateOutbound {
		plan.Warnings = append(plan.Warnings,
			"Emergency network isolation adds an outbound block rule for all programs and enables Windows Firewall profiles. Expect internet, DNS, downloads, cloud features, and Windows Update to stop until restored. This cannot guarantee firmware, hypervisors, separate devices, or out-of-band routes are isolated.")
	}
	plan.Warnings = append(plan.Warnings,
		"Domain policy or MDM can later replace local values. Verification confirms values read back now; it does not prove the complete effective policy or guarantee that no data leaves Windows.",
		"Required diagnostic data may still be sent on common client editions. Security-only diagnostics is available only on editions Microsoft documents as supporting it.",
		"Windows Update, Defender, SmartScreen, certificate revocation, licensing, and essential security services remain enabled. PrivaCage does not hardcode Microsoft IPs or mutate hosts files.")
	return plan, nil
}

func supportsMachinePolicy(edition string) bool {
	edition = strings.ToLower(edition)
	for _, token := range []string{"professional", "enterprise", "education", "iotenterprise", "server"} {
		if strings.Contains(edition, token) {
			return true
		}
	}
	return false
}

func supportsSecurityOnlyTelemetry(edition string) bool {
	edition = strings.ToLower(edition)
	for _, token := range []string{"enterprise", "education", "iotenterprise", "server"} {
		if strings.Contains(edition, token) {
			return true
		}
	}
	return false
}

func collectWindowsMetadata(ctx context.Context) (windowsMetadata, error) {
	script := strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		"$cv = Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction Stop",
		"$edition = [string]$cv.EditionID",
		"$build = 0",
		"if (-not [int]::TryParse([string]$cv.CurrentBuildNumber, [ref]$build)) { throw 'Cannot parse Windows build number.' }",
		"$sid = ''",
		"try {",
		"  $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop",
		"  if ($computer.UserName) { $sid = ([System.Security.Principal.NTAccount]::new([string]$computer.UserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value }",
		"} catch { $sid = '' }",
		"[ordered]@{ edition_id = $edition; build_number = $build; interactive_user_sid = $sid } | ConvertTo-Json -Compress",
	}, "\n")
	output, err := runPowerShellScript(ctx, script)
	if err != nil {
		return windowsMetadata{}, err
	}
	var metadata windowsMetadata
	if err := decodeStrictJSON(output, &metadata); err != nil {
		return windowsMetadata{}, fmt.Errorf("invalid Windows metadata response: %w", err)
	}
	if metadata.EditionID == "" || metadata.BuildNumber < 10240 {
		return windowsMetadata{}, errors.New("Windows version metadata is missing or does not identify a supported Windows 10/11 build")
	}
	return metadata, nil
}

func runPowerShellScript(ctx context.Context, script string) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("Windows PowerShell commands can only run on Windows")
	}
	executable, err := exec.LookPath("powershell.exe")
	if err != nil {
		return nil, errors.New("Windows PowerShell (powershell.exe) was not found")
	}
	encoded := utf16.Encode([]rune(script))
	data := make([]byte, len(encoded)*2)
	for index, value := range encoded {
		binary.LittleEndian.PutUint16(data[index*2:], value)
	}
	command := exec.CommandContext(ctx, executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(data))
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("Windows PowerShell operation exceeded its deadline: %w", ctx.Err())
		}
		detail := strings.TrimSpace(string(output))
		if len(detail) > 1800 {
			detail = detail[len(detail)-1800:]
		}
		if detail == "" {
			detail = err.Error()
		}
		return nil, fmt.Errorf("Windows PowerShell operation failed: %s", detail)
	}
	if len(output) == 0 {
		return nil, errors.New("Windows PowerShell returned no data")
	}
	if len(output) > 1024*1024 {
		return nil, errors.New("Windows PowerShell output exceeded the 1 MiB safety limit")
	}
	return output, nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff")))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("unexpected additional JSON value")
		}
		return fmt.Errorf("invalid trailing JSON data: %w", err)
	}
	return nil
}

func isWindowsAdministrator(ctx context.Context) (bool, error) {
	script := strings.Join([]string{
		"$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()",
		"$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)",
		"$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator).ToString().ToLowerInvariant()",
	}, "\n")
	output, err := runPowerShellScript(ctx, script)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(strings.ToLower(string(output))) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("could not determine the current Windows administrator token")
	}
}

func isInteractiveInput() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
