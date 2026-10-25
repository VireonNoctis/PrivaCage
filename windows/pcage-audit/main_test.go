package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func boolPointer(value bool) *bool { return &value }
func intPointer(value int) *int { return &value }

func fixtureSnapshot() powershellSnapshot {
	return powershellSnapshot{
		FirewallProfiles: []firewallProfile{
			{Name: "Private", Enabled: boolPointer(false), DefaultInboundAction: "Block", DefaultOutboundAction: "Allow"},
			{Name: "Public", Enabled: boolPointer(true), DefaultInboundAction: "Block", DefaultOutboundAction: "Block"},
			{Name: "Domain", Enabled: boolPointer(true), DefaultInboundAction: "Block", DefaultOutboundAction: "Allow"},
		},
		DiagnosticData: registryPolicy{Configured: true, Value: intPointer(0)},
		AppPrivacy: appPrivacyPolicies{
			Location: registryPolicy{Configured: true, Value: intPointer(2)},
			Camera: registryPolicy{Configured: true, Value: intPointer(1)},
			Microphone: registryPolicy{Configured: true, Value: intPointer(0)},
		},
	}
}

func TestBuildReportUsesStableProfileOrderAndConservativeStatuses(t *testing.T) {
	generatedAt := time.Date(2026, 10, 25, 10, 30, 0, 0, time.FixedZone("test", 3600))
	report := buildReport(fixtureSnapshot(), generatedAt)
	if report.SchemaVersion != 1 || report.Platform != "windows" || !report.ReadOnly {
		t.Fatalf("unexpected report metadata: %+v", report)
	}
	if report.GeneratedAt.Location() != time.UTC {
		t.Fatalf("generated time should be normalized to UTC: %s", report.GeneratedAt.Location())
	}
	if report.Summary.Total != 7 {
		t.Fatalf("want 7 checks, got %d", report.Summary.Total)
	}
	if got := []string{report.Checks[0].ID, report.Checks[1].ID, report.Checks[2].ID}; strings.Join(got, ",") != "firewall.domain,firewall.private,firewall.public" {
		t.Fatalf("firewall checks are not deterministic: %v", got)
	}
	if report.Checks[0].Status != statusReview || report.Checks[0].Severity != "low" {
		t.Fatalf("default outbound allow should be a low-severity review, got %+v", report.Checks[0])
	}
	if report.Checks[1].Status != statusReview || report.Checks[1].Severity != "high" {
		t.Fatalf("disabled profile should be a high-severity review, got %+v", report.Checks[1])
	}
	if report.Checks[2].Status != statusOK {
		t.Fatalf("profile with enabled firewall and blocked defaults should be ok, got %+v", report.Checks[2])
	}
	if report.Summary.OK != 2 || report.Summary.Review != 5 || report.Summary.Unknown != 0 || report.Summary.NotConfigured != 0 {
		t.Fatalf("summary counts do not match findings: %+v", report.Summary)
	}
}

func TestUnconfiguredAndUnreadablePoliciesStayDistinct(t *testing.T) {
	snapshot := powershellSnapshot{
		FirewallReadError: true,
		DiagnosticData: registryPolicy{ReadError: true},
		AppPrivacy: appPrivacyPolicies{
			Location: registryPolicy{},
			Camera: registryPolicy{Configured: true, InvalidType: true},
			Microphone: registryPolicy{Configured: true, Value: intPointer(2)},
		},
	}
	report := buildReport(snapshot, time.Now())
	for index := 0; index < 4; index++ {
		if report.Checks[index].Status != statusUnknown {
			t.Errorf("check %s: want unknown, got %s", report.Checks[index].ID, report.Checks[index].Status)
		}
	}
	if report.Checks[4].Status != statusNotConfigured {
		t.Errorf("missing location policy should be not_configured, got %s", report.Checks[4].Status)
	}
	if report.Checks[5].Status != statusUnknown {
		t.Errorf("invalid camera policy type should be unknown, got %s", report.Checks[5].Status)
	}
	if report.Checks[6].Status != statusOK {
		t.Errorf("force-deny microphone policy should be ok, got %s", report.Checks[6].Status)
	}
}

func TestDiagnosticDataValuesAreNotTreatedAsObservedTraffic(t *testing.T) {
	tests := []struct {
		value int
		wantObserved string
		wantStatus string
		wantMeaning string
	}{
		{0, "Security-only", statusReview, "specific editions"},
		{1, "Required diagnostic data", statusReview, "not a measurement of actual network transmission"},
		{2, "legacy/OS-dependent", statusReview, "legacy/OS-dependent"},
		{3, "Optional/full", statusReview, "effective policy"},
		{4, "Unrecognized", statusUnknown, "will not guess"},
	}
	for _, test := range tests {
		observed, status, _, meaning := diagnosticDataMeaning(test.value)
		if !strings.Contains(observed, test.wantObserved) || status != test.wantStatus || !strings.Contains(meaning, test.wantMeaning) {
			t.Errorf("value %d: observed=%q status=%q meaning=%q", test.value, observed, status, meaning)
		}
	}
}

func TestAppPrivacyPolicyValuesAreInterpretedConservatively(t *testing.T) {
	tests := []struct {
		value int
		wantStatus string
		wantObserved string
	}{
		{0, statusReview, "user control"},
		{1, statusReview, "force allow"},
		{2, statusOK, "force deny"},
		{7, statusUnknown, "Unrecognized"},
	}
	for _, test := range tests {
		finding := appPrivacyCheck("camera", "Windows app camera policy", registryPolicy{Configured: true, Value: intPointer(test.value)})
		if finding.Status != test.wantStatus || !strings.Contains(strings.ToLower(finding.Observed), strings.ToLower(test.wantObserved)) {
			t.Errorf("value %d: got status=%q observed=%q", test.value, finding.Status, finding.Observed)
		}
	}
	missing := appPrivacyCheck("camera", "Windows app camera policy", registryPolicy{})
	if missing.Status != statusNotConfigured {
		t.Fatalf("missing policy must not be treated as denied or allowed: %+v", missing)
	}
}

func TestDecodeSnapshotRejectsUnknownFieldsAndExtraJSONValues(t *testing.T) {
	valid, err := json.Marshal(fixtureSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	withUnknownField := append([]byte(strings.TrimSuffix(string(valid), "}")), []byte(",\"unexpected\":true}")...)
	if _, err := decodeSnapshot(withUnknownField); err == nil {
		t.Fatal("unknown top-level JSON field must be rejected")
	}
	if _, err := decodeSnapshot(append(valid, []byte(" {}")...)); err == nil {
		t.Fatal("multiple JSON documents must be rejected")
	}
	if _, err := decodeSnapshot(nil); err == nil {
		t.Fatal("empty snapshot must be rejected")
	}
	if _, err := decodeSnapshot(make([]byte, maximumSnapshotBytes+1)); err == nil {
		t.Fatal("oversized snapshot must be rejected")
	}
}

func TestExecuteRefusesToRunOnNonWindowsPlatforms(t *testing.T) {
	err := execute([]string{"--format", "json"}, nil, nil, "linux")
	if err == nil || !strings.Contains(err.Error(), "requires Windows 10/11") {
		t.Fatalf("expected a clear Windows-only error, got %v", err)
	}
}
