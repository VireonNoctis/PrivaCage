package main

import (
	"fmt"
	"strings"
	"time"
)

const (
	statusOK             = "ok"
	statusReview         = "review"
	statusNotConfigured  = "not_configured"
	statusUnknown        = "unknown"
	firewallSource       = "https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile"
	diagnosticDataSource = "https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization"
	appPrivacySource     = "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy"
)

type auditCheck struct {
	ID             string "json:\"id\""
	Title          string "json:\"title\""
	Category       string "json:\"category\""
	Status         string "json:\"status\""
	Severity       string "json:\"severity\""
	Observed       string "json:\"observed\""
	Meaning        string "json:\"meaning\""
	Recommendation string "json:\"recommendation,omitempty\""
	SourceURL      string "json:\"source_url\""
}

type auditSummary struct {
	Total         int "json:\"total\""
	OK            int "json:\"ok\""
	Review        int "json:\"review\""
	NotConfigured int "json:\"not_configured\""
	Unknown       int "json:\"unknown\""
}

type auditReport struct {
	SchemaVersion int          "json:\"schema_version\""
	GeneratedAt   time.Time    "json:\"generated_at\""
	Platform      string       "json:\"platform\""
	ReadOnly      bool         "json:\"read_only\""
	Summary       auditSummary "json:\"summary\""
	Checks        []auditCheck "json:\"checks\""
	Limitations   []string     "json:\"limitations\""
}

func buildReport(snapshot powershellSnapshot, generatedAt time.Time) auditReport {
	checks := make([]auditCheck, 0, 7)
	checks = append(checks, firewallChecks(snapshot)...)
	checks = append(checks, policyCheck(
		"diagnostics.allow_telemetry",
		"Windows diagnostic-data policy",
		"diagnostics",
		snapshot.DiagnosticData,
		diagnosticDataSource,
		diagnosticDataMeaning,
		"Review Settings > Privacy & security > Diagnostics & feedback and any organization-managed policy.",
	))
	checks = append(checks,
		appPrivacyCheck("location", "Windows app location policy", snapshot.AppPrivacy.Location),
		appPrivacyCheck("camera", "Windows app camera policy", snapshot.AppPrivacy.Camera),
		appPrivacyCheck("microphone", "Windows app microphone policy", snapshot.AppPrivacy.Microphone),
	)
	return auditReport{
		SchemaVersion: 1,
		GeneratedAt:   generatedAt.UTC(),
		Platform:      "windows",
		ReadOnly:      true,
		Summary:       summarize(checks),
		Checks:        checks,
		Limitations: []string{
			"This is a point-in-time configuration audit. It does not inspect packet contents, destinations, app network activity, or prove that any data was sent.",
			"Firewall profile state does not show which rules matched a connection or establish that an application is safe.",
			"Registry policy findings cover machine-level policy values only. They do not calculate the effective combination of user policy, MDM, Windows edition, per-app settings, and unmanaged defaults.",
			"Location, camera, and microphone findings cover Windows App Privacy policy for Windows apps; they are not a universal access barrier for every desktop program, service, driver, or operating-system component.",
			"The command is read-only and makes no network requests. It does not change settings or create firewall rules.",
		},
	}
}

func firewallChecks(snapshot powershellSnapshot) []auditCheck {
	expected := []string{"Domain", "Private", "Public"}
	found := make(map[string]firewallProfile, len(snapshot.FirewallProfiles))
	for _, profile := range snapshot.FirewallProfiles {
		found[strings.ToLower(profile.Name)] = profile
	}
	checks := make([]auditCheck, 0, len(expected))
	for _, name := range expected {
		id := "firewall." + strings.ToLower(name)
		profile, exists := found[strings.ToLower(name)]
		if snapshot.FirewallReadError || !exists {
			observed := "Profile state unavailable"
			meaning := "PrivaCage could not confirm this profile's effective firewall configuration. Unknown does not mean enabled or disabled."
			if !snapshot.FirewallReadError {
				meaning = "Windows did not return this firewall profile in the ActiveStore query. No state is inferred."
			}
			checks = append(checks, auditCheck{
				ID: id, Title: name + " firewall profile", Category: "firewall",
				Status: statusUnknown, Severity: "unknown", Observed: observed,
				Meaning: meaning, Recommendation: "Open Windows Security > Firewall & network protection and inspect this profile.",
				SourceURL: firewallSource,
			})
			continue
		}
		if profile.Enabled == nil {
			checks = append(checks, auditCheck{
				ID: id, Title: name + " firewall profile", Category: "firewall",
				Status: statusUnknown, Severity: "unknown", Observed: "Enabled state not returned",
				Meaning: "Windows did not return a boolean enabled state; PrivaCage will not infer it from other fields.",
				Recommendation: "Inspect the profile in Windows Security.",
				SourceURL: firewallSource,
			})
			continue
		}
		observed := fmt.Sprintf("enabled=%t; default inbound=%s; default outbound=%s",
			*profile.Enabled, actionOrUnknown(profile.DefaultInboundAction), actionOrUnknown(profile.DefaultOutboundAction))
		finding := auditCheck{
			ID: id, Title: name + " firewall profile", Category: "firewall",
			Status: statusOK, Severity: "info", Observed: observed, SourceURL: firewallSource,
		}
		switch {
		case !*profile.Enabled:
			finding.Status = statusReview
			finding.Severity = "high"
			finding.Meaning = "The Windows firewall profile is disabled. Other network controls may exist, but PrivaCage did not verify them."
			finding.Recommendation = "Review and enable the profile in Windows Security, unless an administrator intentionally manages a different firewall."
		case strings.EqualFold(profile.DefaultInboundAction, "Allow"):
			finding.Status = statusReview
			finding.Severity = "medium"
			finding.Meaning = "The profile's default inbound action is Allow. This is a configuration signal to review, not evidence that a connection was accepted."
			finding.Recommendation = "Review inbound policy with Windows Security or your administrator before changing a managed device."
		case strings.EqualFold(profile.DefaultOutboundAction, "Allow"):
			finding.Status = statusReview
			finding.Severity = "low"
			finding.Meaning = "Outbound connections are allowed by default unless a matching rule blocks them. This does not prove any app connected or sent data."
			finding.Recommendation = "Review outbound application rules if you need app-specific network restrictions; do not assume that an enabled firewall blocks all telemetry."
		case strings.EqualFold(profile.DefaultInboundAction, "Block") && strings.EqualFold(profile.DefaultOutboundAction, "Block"):
			finding.Meaning = "Both default inbound and outbound actions are Block. Check that required applications have deliberate allow rules."
		default:
			finding.Status = statusUnknown
			finding.Severity = "unknown"
			finding.Meaning = "The firewall is enabled, but one or both default actions have an unrecognized or unconfigured value. PrivaCage does not infer the effective rule outcome."
			finding.Recommendation = "Inspect the profile and effective policy in Windows Security or PowerShell."
		}
		checks = append(checks, finding)
	}
	return checks
}

func policyCheck(
	id, title, category string,
	setting registryPolicy,
	source string,
	meaningForValue func(int) (string, string, string, string),
	recommendation string,
) auditCheck {
	finding := auditCheck{
		ID: id, Title: title, Category: category, Status: statusNotConfigured,
		Severity: "info", Observed: "No machine-level policy value found",
		Meaning: "This only means the queried machine-policy value is absent. It does not establish the effective Windows setting; user settings, user policy, MDM, edition, and OS version may affect it.",
		Recommendation: recommendation, SourceURL: source,
	}
	if setting.ReadError {
		finding.Status = statusUnknown
		finding.Severity = "unknown"
		finding.Observed = "Policy value could not be read"
		finding.Meaning = "The registry query failed. PrivaCage does not treat a read failure as an absent policy."
		return finding
	}
	if !setting.Configured {
		return finding
	}
	if setting.InvalidType || setting.Value == nil {
		finding.Status = statusUnknown
		finding.Severity = "unknown"
		finding.Observed = "Policy exists but is not a readable DWORD"
		finding.Meaning = "The policy value has an unexpected registry type; its meaning is not inferred."
		return finding
	}
	finding.Observed, finding.Status, finding.Severity, finding.Meaning = meaningForValue(*setting.Value)
	return finding
}

func diagnosticDataMeaning(value int) (string, string, string, string) {
	switch value {
	case 0:
		return "Policy value 0 — Security-only diagnostic-data value", statusReview, "info",
			"Microsoft documents value 0 as Security-only on specific editions; on other editions it can behave like value 1. The registry value alone does not prove what left the device."
	case 1:
		return "Policy value 1 — Required diagnostic data", statusReview, "info",
			"The machine policy requests Required diagnostic data. This describes the configured policy value, not a measurement of actual network transmission."
	case 2:
		return "Policy value 2 — Enhanced diagnostic data (legacy/OS-dependent)", statusReview, "medium",
			"Value 2 is legacy/OS-dependent. Confirm how the installed Windows version interprets it before drawing conclusions."
	case 3:
		return "Policy value 3 — Optional/full diagnostic data", statusReview, "medium",
			"The machine policy is configured for Optional/full diagnostic data. The actual effective policy can also depend on version and management configuration."
	default:
		return fmt.Sprintf("Unrecognized policy value %d", value), statusUnknown, "unknown",
			"PrivaCage does not recognize this value and will not guess its meaning."
	}
}

func appPrivacyCheck(kind, title string, setting registryPolicy) auditCheck {
	finding := auditCheck{
		ID: "app_privacy." + kind, Title: title, Category: "app_privacy",
		Status: statusNotConfigured, Severity: "info",
		Observed: "No machine-level forced policy value found",
		Meaning: "No machine-level force-allow/force-deny policy was found for this capability. This does not say whether the current user or a specific app has access.",
		Recommendation: "Review Windows Settings > Privacy & security and the setting for the relevant capability.",
		SourceURL: appPrivacySource,
	}
	if setting.ReadError {
		finding.Status = statusUnknown
		finding.Severity = "unknown"
		finding.Observed = "Policy value could not be read"
		finding.Meaning = "The registry query failed. PrivaCage does not treat a read failure as an absent policy."
		return finding
	}
	if !setting.Configured {
		return finding
	}
	if setting.InvalidType || setting.Value == nil {
		finding.Status = statusUnknown
		finding.Severity = "unknown"
		finding.Observed = "Policy exists but is not a readable DWORD"
		finding.Meaning = "The policy value has an unexpected registry type; its meaning is not inferred."
		return finding
	}
	switch *setting.Value {
	case 0:
		finding.Status = statusReview
		finding.Severity = "info"
		finding.Observed = "Policy value 0 — user control"
		finding.Meaning = "The machine policy leaves the user in control. Per-app settings and traditional desktop programs are not fully represented by this policy."
		finding.Recommendation = "Review individual app permissions in Windows Settings."
	case 1:
		finding.Status = statusReview
		finding.Severity = "medium"
		finding.Observed = "Policy value 1 — force allow"
		finding.Meaning = "The machine policy forces Windows-app access to this capability. This does not prove an app used it."
		finding.Recommendation = "Review the machine policy with the device administrator if forced access is not intended."
	case 2:
		finding.Status = statusOK
		finding.Severity = "info"
		finding.Observed = "Policy value 2 — force deny"
		finding.Meaning = "The machine policy forces denial for the Windows-app permission scope covered by this policy. It is not a universal barrier for every desktop program or system component."
		finding.Recommendation = "No change is needed for this policy value; review desktop-app and system-component scope separately."
	default:
		finding.Status = statusUnknown
		finding.Severity = "unknown"
		finding.Observed = fmt.Sprintf("Unrecognized policy value %d", *setting.Value)
		finding.Meaning = "PrivaCage does not recognize this value and will not infer whether access is allowed or denied."
	}
	return finding
}

func actionOrUnknown(action string) string {
	if strings.TrimSpace(action) == "" {
		return "unknown"
	}
	return action
}

func summarize(checks []auditCheck) auditSummary {
	summary := auditSummary{Total: len(checks)}
	for _, finding := range checks {
		switch finding.Status {
		case statusOK:
			summary.OK++
		case statusReview:
			summary.Review++
		case statusNotConfigured:
			summary.NotConfigured++
		default:
			summary.Unknown++
		}
	}
	return summary
}
