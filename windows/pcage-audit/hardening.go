package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
		SchemaVersion:          1,
		Profile:                profile,
		EditionID:              metadata.EditionID,
		BuildNumber:            metadata.BuildNumber,
		Changes:                make([]policyChange, 0, 32),
		Skipped:                make([]string, 0, 8),
		Warnings:               make([]string, 0, 8),
		BlockOutboundByDefault: blockOutboundByDefault,
		IsolateOutbound:        isolateOutbound,
	}
	add := func(hive, subKey, name string, value int, description, source string) {
		plan.Changes = append(plan.Changes, policyChange{
			Hive: hive, SubKey: subKey, Name: name, Value: value,
			Description: description, SourceURL: source,
		})
	}

	isClient := supportsClientPrivacyPolicies(metadata.EditionID)
	sid := metadata.InteractiveUserSID
	if sid != "" && isClient {
		add("Users", sid+"\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", "Enabled", 0,
			"Disable the advertising-ID preference for the initiating interactive user. This does not erase previously collected profiles.",
			"https://learn.microsoft.com/en-us/windows/privacy/windows-privacy-compliance-guide")
	} else if sid == "" && isClient {
		plan.Skipped = append(plan.Skipped, "The current user's advertising-ID and tailored-experience policies were skipped because the interactive user SID was not available. Machine policies remain device-scoped.")
	}

	if !supportsMachinePolicy(metadata.EditionID) {
		plan.Skipped = append(plan.Skipped,
			"Documented machine policy controls are not supported for this Windows Home/Core edition; no machine registry policy is written.")
	} else {
		telemetryLevel := 1
		telemetryDescription := "Use Required diagnostic data, the lowest documented diagnostic-data level for mainstream Pro editions. Required diagnostic data is not zero Windows traffic."
		if supportsSecurityOnlyTelemetry(metadata.EditionID, metadata.BuildNumber) {
			telemetryLevel = 0
			telemetryDescription = "Select the documented Diagnostic data off policy on an edition supporting value 0. This controls Windows diagnostic data only and does not guarantee zero system communications."
		}
		add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "AllowTelemetry", telemetryLevel, telemetryDescription, securityPolicyCSP)

		if isClient {
			if metadata.BuildNumber >= 17134 {
				add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "ConfigureTelemetryOptInSettingsUx", 1,
					"Prevent users from changing the diagnostic-data level in the Settings UI; this does not prevent administrators or higher-priority management policy from changing policy.",
					securityPolicyCSP)
			} else {
				plan.Skipped = append(plan.Skipped, "ConfigureTelemetryOptInSettingsUx requires Windows build 17134 or newer.")
			}
			if metadata.BuildNumber >= 14393 {
				add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo", "DisabledByGroupPolicy", 1,
					"Turn off the advertising identifier through the documented machine policy.", privacyPolicyCSP)
			} else {
				plan.Skipped = append(plan.Skipped, "The Windows advertising-identifier machine policy requires build 14393 or newer.")
			}
			if metadata.BuildNumber >= 16299 {
				add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "EnableActivityFeed", 0,
					"Disable Activity Feed publishing and cloud roaming.", privacyPolicyCSP)
				add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "PublishUserActivities", 0,
					"Prevent Windows apps and the OS from publishing User Activities.", privacyPolicyCSP)
			} else {
				plan.Skipped = append(plan.Skipped, "Activity Feed and PublishUserActivities controls require Windows build 16299 or newer.")
			}
			if metadata.BuildNumber >= 17134 {
				add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "UploadUserActivities", 0,
					"Prevent User Activities from being uploaded to Microsoft cloud services.", privacyPolicyCSP)
			} else {
				plan.Skipped = append(plan.Skipped, "UploadUserActivities requires Windows build 17134 or newer.")
			}
			if metadata.BuildNumber >= 17763 {
				add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "AllowCrossDeviceClipboard", 0,
					"Prevent clipboard contents from syncing to other devices logged in to the same account.", privacyPolicyCSP)
				add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "AllowDeviceNameInDiagnosticData", 0,
					"Disallow inclusion of the device name in Windows diagnostic data.", securityPolicyCSP)
			} else {
				plan.Skipped = append(plan.Skipped, "Cross-device clipboard and diagnostic device-name policies require Windows build 17763 or newer.")
			}
			add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\InputPersonalization", "AllowInputPersonalization", 0,
				"Disable online speech-recognition services through the documented policy.", privacyPolicyCSP)
			if sid != "" && metadata.BuildNumber >= 15063 {
				add("Users", sid+"\\Software\\Policies\\Microsoft\\Windows\\CloudContent", "DisableTailoredExperiencesWithDiagnosticData", 1,
					"Prevent diagnostic data being used for tailored experiences for the initiating user.", experiencePolicyCSP)
			} else if sid == "" {
				plan.Skipped = append(plan.Skipped, "DisableTailoredExperiencesWithDiagnosticData was skipped because no initiating user SID was available.")
			} else {
				plan.Skipped = append(plan.Skipped, "DisableTailoredExperiencesWithDiagnosticData requires Windows build 15063 or newer.")
			}
		} else {
			plan.Skipped = append(plan.Skipped, "Client-only advertising ID, Activity Feed, clipboard-sync, online speech, and tailored-experience policies are not applied to Windows Server.")
		}

		if metadata.BuildNumber >= 22000 || (strings.Contains(strings.ToLower(metadata.EditionID), "server") && metadata.BuildNumber >= 20348) {
			add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "LimitDiagnosticLogCollection", 1,
				"Limit Windows diagnostic-log collection on supported Windows 11 and Windows Server 2022 builds.", securityPolicyCSP)
			add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "LimitDumpCollection", 1,
				"Limit Windows Error Reporting dumps to the documented mini/triage scope on supported builds.", securityPolicyCSP)
		} else {
			plan.Skipped = append(plan.Skipped, "LimitDiagnosticLogCollection and LimitDumpCollection require Windows 11 build 22000 or Windows Server 2022 build 20348 or newer.")
		}

		if profile == "strict" && isClient {
			if metadata.BuildNumber >= 17763 {
				add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\System", "AllowClipboardHistory", 0,
					"Disallow storing Windows clipboard history in memory.", "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience")
			} else {
				plan.Skipped = append(plan.Skipped, "AllowClipboardHistory requires Windows build 17763 or newer.")
			}
			if metadata.BuildNumber >= 14393 {
				appPrivacy := "SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy"
				for _, item := range []struct {
					name        string
					description string
				}{
					{"LetAppsAccessLocation", "Force-deny location access for Windows apps; traditional desktop programs and OS components may fall outside this policy scope."},
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
			} else {
				plan.Skipped = append(plan.Skipped, "Windows App Privacy force-deny policies require Windows build 14393 or newer.")
			}
			add("LocalMachine", "SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting", "Disabled", 1,
				"Disable Windows Error Reporting policy. This removes a troubleshooting path and does not disable every diagnostic channel.", errorReportingPolicyCSP)
		} else if profile == "strict" && !isClient {
			plan.Skipped = append(plan.Skipped, "The strict Windows-app capability restrictions, clipboard-history control, and Windows Error Reporting policy are not applied to Windows Server.")
		}
	}

	if blockOutboundByDefault {
		plan.Warnings = append(plan.Warnings,
			"Outbound defaults will be Block for all three firewall profiles. Explicit allow rules may still permit connections; apps, downloads, cloud functions, and updates can stop working.")
	}
	if isolateOutbound {
		plan.Warnings = append(plan.Warnings,
			"Emergency isolation adds an outbound block rule for all programs and enables Windows Firewall profiles. Expect internet, DNS, downloads, cloud features, and Windows Update to stop until restored. This cannot guarantee firmware, hypervisors, separate devices, or out-of-band routes are isolated.")
	}
	plan.Warnings = append(plan.Warnings,
		"Domain policy or MDM can later replace local values. Verification confirms current readback; it does not prove the complete effective policy or guarantee that no data leaves Windows.",
		"Required diagnostic data remains on mainstream client editions. Diagnostic data off is documented only for Enterprise, Education, and Server editions; this does not disable all system communications.",
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

func supportsClientPrivacyPolicies(edition string) bool {
	edition = strings.ToLower(edition)
	return supportsMachinePolicy(edition) && !strings.Contains(edition, "server")
}

func supportsSecurityOnlyTelemetry(edition string, buildNumber int) bool {
	edition = strings.ToLower(edition)
	if strings.Contains(edition, "iotenterprise") {
		return false
	}
	if strings.Contains(edition, "enterprise") || strings.Contains(edition, "education") || strings.Contains(edition, "server") {
		return true
	}
	return false
}

func collectWindowsMetadata(ctx context.Context) (windowsMetadata, error) {
	script := strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		"$ProgressPreference = 'SilentlyContinue'",
		"$cv = Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction Stop",
		"$edition = [string]$cv.EditionID",
		"$build = 0",
		"if (-not [int]::TryParse([string]$cv.CurrentBuildNumber, [ref]$build)) { throw 'Cannot parse Windows build number.' }",
		"$sid = ''",
		"if ($env:PRIVACAGE_INTERACTIVE -eq 'true') { $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }",
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
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return nil, errors.New("SystemRoot is not set; refusing to resolve an elevated PowerShell executable through PATH")
	}
	candidates := []string{
		filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
	}
	if runtime.GOARCH == "386" {
		candidates = append([]string{
			filepath.Join(systemRoot, "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
		}, candidates...)
	}
	executable := ""
	for _, candidate := range candidates {
		info, statErr := os.Stat(candidate)
		if statErr == nil && !info.IsDir() {
			executable = candidate
			break
		}
	}
	if executable == "" {
		return nil, errors.New("the in-box Windows PowerShell executable was not found at its SystemRoot path")
	}
	encoded := utf16.Encode([]rune(script))
	data := make([]byte, len(encoded)*2)
	for index, value := range encoded {
		binary.LittleEndian.PutUint16(data[index*2:], value)
	}
	command := exec.CommandContext(ctx, executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(data))
	command.Env = make([]string, 0, len(os.Environ())+1)
	for _, environment := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(environment), "PRIVACAGE_INTERACTIVE=") {
			command.Env = append(command.Env, environment)
		}
	}
	command.Env = append(command.Env, "PRIVACAGE_INTERACTIVE="+strconv.FormatBool(isInteractiveInput()))
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("Windows PowerShell operation exceeded its deadline: %w", ctx.Err())
		}
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 1800 {
			detail = detail[len(detail)-1800:]
		}
		if detail == "" {
			detail = err.Error()
		}
		return nil, fmt.Errorf("Windows PowerShell operation failed: %s", detail)
	}
	if stderr.Len() != 0 {
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 1800 {
			detail = detail[len(detail)-1800:]
		}
		return nil, fmt.Errorf("Windows PowerShell emitted an error stream despite exit code 0: %s", detail)
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
