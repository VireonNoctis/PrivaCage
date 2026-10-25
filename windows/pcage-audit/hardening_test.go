package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEditionGatesForMachinePolicyAndSecurityDiagnostics(t *testing.T) {
	tests := []struct {
		edition  string
		build    int
		machine  bool
		security bool
	}{
		{"Core", 22631, false, false},
		{"Professional", 22631, true, false},
		{"Enterprise", 22631, true, true},
		{"Education", 22631, true, true},
		{"IoTEnterprise", 22631, true, false},
		{"ServerStandard", 14393, true, true},
		{"ServerStandard", 20348, true, false},
	}
	for _, test := range tests {
		if got := supportsMachinePolicy(test.edition); got != test.machine {
			t.Errorf("supportsMachinePolicy(%q)=%t, want %t", test.edition, got, test.machine)
		}
		if got := supportsSecurityOnlyTelemetry(test.edition, test.build); got != test.security {
			t.Errorf("supportsSecurityOnlyTelemetry(%q, %d)=%t, want %t", test.edition, test.build, got, test.security)
		}
	}
}

func TestBalancedPlanUsesEditionAppropriateDiagnosticSetting(t *testing.T) {
	metadata := windowsMetadata{EditionID: "Professional", BuildNumber: 22631, InteractiveUserSID: "S-1-5-21-111-222-333-1001"}
	plan, err := buildHardeningPlan("balanced", metadata, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SchemaVersion != 1 || plan.Profile != "balanced" || plan.BlockOutboundByDefault || plan.IsolateOutbound {
		t.Fatalf("unexpected balanced plan metadata: %+v", plan)
	}
	var telemetry, activity, upload, tailored, limitLogs, clipboardSync, deviceName bool
	for _, change := range plan.Changes {
		switch change.Name {
		case "AllowTelemetry":
			telemetry = true
			if change.Value != 1 {
				t.Errorf("Professional must use Required diagnostics (1), got %d", change.Value)
			}
		case "EnableActivityFeed":
			activity = change.Value == 0
		case "UploadUserActivities":
			upload = change.Value == 0
		case "DisableTailoredExperiencesWithDiagnosticData":
			tailored = change.Value == 1 && change.Hive == "Users"
		case "LimitDiagnosticLogCollection":
			limitLogs = change.Value == 1
		case "AllowCrossDeviceClipboard":
			clipboardSync = change.Value == 0
		case "AllowDeviceNameInDiagnosticData":
			deviceName = change.Value == 0
		}
	}
	if !telemetry || !activity || !upload || !tailored || !limitLogs || !clipboardSync || !deviceName {
		t.Fatalf("balanced plan missing documented controls: %+v", plan.Changes)
	}
	enterprise, err := buildHardeningPlan("balanced", windowsMetadata{EditionID: "Enterprise", BuildNumber: 22631}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range enterprise.Changes {
		if change.Name == "AllowTelemetry" && change.Value != 0 {
			t.Errorf("Enterprise should select documented Security-level value 0, got %d", change.Value)
		}
	}
}

func TestStrictPlanAddsWindowsAppPrivacyDenials(t *testing.T) {
	plan, err := buildHardeningPlan("strict", windowsMetadata{
		EditionID: "Professional", BuildNumber: 22631, InteractiveUserSID: "S-1-5-21-111-222-333-1001",
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{})
	for _, change := range plan.Changes {
		key := change.Hive + "|" + change.SubKey + "|" + change.Name
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate change target: %s", key)
		}
		seen[key] = struct{}{}
	}
	required := []string{
		"LetAppsAccessLocation", "LetAppsAccessCamera", "LetAppsAccessMicrophone",
		"LetAppsAccessContacts", "LetAppsAccessCalendar", "LetAppsAccessEmail",
		"LetAppsAccessMessaging", "LetAppsAccessCallHistory", "LetAppsAccessTasks",
		"LetAppsAccessNotifications", "LetAppsGetDiagnosticInfo", "AllowClipboardHistory", "Disabled",
	}
	for _, name := range required {
		found := false
		for _, change := range plan.Changes {
			if change.Name != name {
				continue
			}
			found = true
			if name == "AllowClipboardHistory" && change.Value != 0 {
				t.Errorf("AllowClipboardHistory should be 0, got %d", change.Value)
			}
			if name == "Disabled" && change.Value != 1 {
				t.Errorf("Windows Error Reporting Disabled should equal 1, got %d", change.Value)
			}
			if name != "Disabled" && change.Value != 2 {
				t.Errorf("%s force-deny value should equal 2, got %d", name, change.Value)
			}
		}
		if !found {
			t.Errorf("strict profile missing %s", name)
		}
	}
	if len(plan.Changes) > 32 {
		t.Fatalf("strict profile exceeded the transactional maximum: %d", len(plan.Changes))
	}
}

func TestHomePlanDoesNotPretendMachinePoliciesAreSupported(t *testing.T) {
	plan, err := buildHardeningPlan("strict", windowsMetadata{
		EditionID: "Core", BuildNumber: 22631, InteractiveUserSID: "S-1-5-21-111-222-333-1001",
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Name != "Enabled" {
		t.Fatalf("Home plan should only change supported user advertising preference, got %+v", plan.Changes)
	}
	if len(plan.Skipped) == 0 {
		t.Fatal("Home plan should state which machine policies were skipped")
	}
}

func TestPlanRejectsInvalidProfilesAndConflictingNetworkModes(t *testing.T) {
	metadata := windowsMetadata{EditionID: "Professional", BuildNumber: 22631}
	if _, err := buildHardeningPlan("aggressive-unknown", metadata, false, false); err == nil {
		t.Fatal("unknown hardening profile must be rejected")
	}
	if _, err := buildHardeningPlan("balanced", metadata, true, true); err == nil {
		t.Fatal("conflicting network modes must be rejected")
	}
	if _, err := buildHardeningPlan("balanced", windowsMetadata{EditionID: "Professional", BuildNumber: 0}, false, false); err == nil {
		t.Fatal("invalid Windows build must be rejected")
	}
}

func TestStrictJSONRejectsUnknownFieldsAndTrailingDocuments(t *testing.T) {
	var target struct {
		Name string "json:\"name\""
	}
	if err := decodeStrictJSON([]byte("{\"name\":\"test\"}"), &target); err != nil {
		t.Fatalf("valid JSON should be accepted: %v", err)
	}
	if err := decodeStrictJSON([]byte("{\"name\":\"test\",\"extra\":1}"), &target); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
	if err := decodeStrictJSON([]byte("{\"name\":\"test\"} {\"name\":\"second\"}"), &target); err == nil {
		t.Fatal("a second JSON value must be rejected")
	}
	if err := decodeStrictJSON([]byte("{malformed"), &target); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
}

func TestQuoteWindowsArgumentPreservesSpacesQuotesAndTrailingSlashes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"plain", "plain"},
		{"folder with space", "\"folder with space\""},
		{"a\"b", "\"a\\\"b\""},
		{"C:\\folder with space\\", "\"C:\\folder with space\\\\\""},
	}
	for _, test := range tests {
		if got := quoteWindowsArgument(test.input); got != test.want {
			t.Errorf("quoteWindowsArgument(%q)=%q, want %q", test.input, got, test.want)
		}
	}
}

func TestPlanWarningsDescribeTheDiagnosticDataLimit(t *testing.T) {
	plan, err := buildHardeningPlan("balanced", windowsMetadata{EditionID: "Professional", BuildNumber: 22631}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.ToLower(strings.Join(plan.Warnings, "\n"))
	if !strings.Contains(joined, "required diagnostic data") || !strings.Contains(joined, "does not") {
		t.Fatalf("expected explicit limits in warnings: %s", joined)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(encoded) {
		t.Fatal("plan should serialize to valid JSON")
	}
}
