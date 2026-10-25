package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureEntry() trackerEntry {
	return trackerEntry{
		ID: "example-analytics-sdk",
		Name: "Example Analytics SDK",
		Category: "analytics",
		Indicators: trackerIndicators{
			Domains: []string{"metrics.example.org"},
			SDKPatterns: []string{"org.example.analytics.**"},
		},
		Confidence: "medium",
		Status: "active",
		LastVerified: "2026-10-20",
		Evidence: []trackerEvidence{{
			URL: "https://docs.example.org/analytics-sdk",
			Description: "Example test fixture only; not a real tracker signature.",
		}},
	}
}

func fixtureDatabase() trackerDatabase {
	return trackerDatabase{
		SchemaVersion: 1,
		UpdatedAt: "2026-10-21",
		Entries: []trackerEntry{fixtureEntry()},
	}
}

func validateFixture(document trackerDatabase, maxAgeDays *int, today time.Time) []string {
	return validateTrackerDatabase(document, maxAgeDays, today)
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestTrackerDatabaseAcceptsEmptyAndValidDocuments(t *testing.T) {
	empty := trackerDatabase{SchemaVersion: 1, UpdatedAt: "2026-10-21", Entries: []trackerEntry{}}
	today, _ := parseDate("2026-10-23", "today")
	if errorsFound := validateFixture(empty, nil, today); len(errorsFound) != 0 {
		t.Fatalf("empty database rejected: %v", errorsFound)
	}
	if errorsFound := validateFixture(fixtureDatabase(), nil, today); len(errorsFound) != 0 {
		t.Fatalf("valid fixture rejected: %v", errorsFound)
	}
}

func TestTrackerDatabaseRejectsInvalidRecords(t *testing.T) {
	today, _ := parseDate("2026-10-23", "today")
	tests := []struct {
		name string
		mutate func(*trackerDatabase)
		want string
	}{
		{
			name: "duplicate id",
			mutate: func(db *trackerDatabase) { db.Entries = append(db.Entries, db.Entries[0]) },
			want: "duplicate id",
		},
		{
			name: "non-HTTPS evidence",
			mutate: func(db *trackerDatabase) { db.Entries[0].Evidence[0].URL = "http://docs.example.org/analytics-sdk" },
			want: "must use HTTPS",
		},
		{
			name: "URL credentials",
			mutate: func(db *trackerDatabase) { db.Entries[0].Evidence[0].URL = "https://user:pass@docs.example.org/analytics-sdk" },
			want: "must not contain credentials",
		},
		{
			name: "out-of-range port",
			mutate: func(db *trackerDatabase) { db.Entries[0].Evidence[0].URL = "https://docs.example.org:99999/analytics-sdk" },
			want: "port must be between 1 and 65535",
		},
		{
			name: "URL used as domain",
			mutate: func(db *trackerDatabase) { db.Entries[0].Indicators.Domains = []string{"https://metrics.example.org/path"} },
			want: "valid hostname",
		},
		{
			name: "invalid calendar date",
			mutate: func(db *trackerDatabase) { db.Entries[0].LastVerified = "2026-02-30" },
			want: "valid canonical YYYY-MM-DD",
		},
		{
			name: "malformed SDK pattern",
			mutate: func(db *trackerDatabase) { db.Entries[0].Indicators.SDKPatterns = []string{"contains spaces and no package syntax"} },
			want: "dotted package/class pattern",
		},
		{
			name: "nonterminal wildcard",
			mutate: func(db *trackerDatabase) { db.Entries[0].Indicators.SDKPatterns = []string{"org.example.*.analytics"} },
			want: "terminal .* or .** wildcard",
		},
		{
			name: "uppercase domain",
			mutate: func(db *trackerDatabase) { db.Entries[0].Indicators.Domains = []string{"Metrics.example.org"} },
			want: "must be lowercase",
		},
		{
			name: "duplicate evidence URL",
			mutate: func(db *trackerDatabase) { db.Entries[0].Evidence = append(db.Entries[0].Evidence, db.Entries[0].Evidence[0]) },
			want: "url is duplicated",
		},
		{
			name: "empty indicators",
			mutate: func(db *trackerDatabase) { db.Entries[0].Indicators = trackerIndicators{} },
			want: "indicators must not be empty",
		},
		{
			name: "empty evidence",
			mutate: func(db *trackerDatabase) { db.Entries[0].Evidence = nil },
			want: "evidence must be a non-empty array",
		},
		{
			name: "unsupported confidence",
			mutate: func(db *trackerDatabase) { db.Entries[0].Confidence = "certain" },
			want: "confidence must be one of",
		},
		{
			name: "unsupported status",
			mutate: func(db *trackerDatabase) { db.Entries[0].Status = "blocked" },
			want: "status must be one of",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := fixtureDatabase()
			test.mutate(&document)
			errorsFound := validateFixture(document, nil, today)
			if len(errorsFound) == 0 || !strings.Contains(errorsFound[0], test.want) {
				t.Fatalf("got errors %v; want an error containing %q", errorsFound, test.want)
			}
		})
	}
}

func TestTrackerDatabaseRejectsUnknownFieldsAtEveryLevel(t *testing.T) {
	data, err := json.Marshal(fixtureDatabase())
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(data), "\"status\":", "\"trusted\":true,\"status\":", 1)
	path := writeTempFile(t, "unknown-field.json", mutated)
	_, err = readTrackerDatabase(path)
	if err == nil || !strings.Contains(err.Error(), "fields must be exactly") {
		t.Fatalf("unknown field was not rejected clearly: %v", err)
	}

	indicatorUnknown := strings.Replace(string(data), "\"sdk_patterns\":[\"org.example.analytics.**\"]", "\"unsupported\":[],\"sdk_patterns\":[\"org.example.analytics.**\"]", 1)
	path = writeTempFile(t, "unknown-indicator-field.json", indicatorUnknown)
	_, err = readTrackerDatabase(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported indicators field") {
		t.Fatalf("unknown indicator field was not rejected: %v", err)
	}

	for _, test := range []struct {
		name string
		input string
	}{
		{"wrong-case top-level key", strings.Replace(string(data), "\"schema_version\":1", "\"SCHEMA_VERSION\":1", 1)},
		{"wrong-case entry key", strings.Replace(string(data), "\"name\":\"Example Analytics SDK\"", "\"Name\":\"Example Analytics SDK\"", 1)},
		{"wrong-case evidence key", strings.Replace(string(data), "\"url\":\"https://docs.example.org/analytics-sdk\"", "\"URL\":\"https://docs.example.org/analytics-sdk\"", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeTempFile(t, "wrong-case.json", test.input)
			_, err := readTrackerDatabase(path)
			if err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("case-mismatched schema key was not rejected: %v", err)
			}
		})
	}
}

func TestTrackerDatabaseRejectsNonCanonicalAndMissingFields(t *testing.T) {
	today, _ := parseDate("2026-10-23", "today")
	document := fixtureDatabase()
	document.UpdatedAt = "2026-10-21T00:00:00Z"
	errorsFound := validateFixture(document, nil, today)
	if len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "canonical YYYY-MM-DD") {
		t.Fatalf("noncanonical updated_at not rejected: %v", errorsFound)
	}
	document = trackerDatabase{SchemaVersion: 1, UpdatedAt: "2026-10-21", Entries: nil}
	errorsFound = validateFixture(document, nil, today)
	if len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "entries must be an array") {
		t.Fatalf("missing entries not rejected: %v", errorsFound)
	}
}

func TestSDKTerminalWildcardsRemainValid(t *testing.T) {
	today, _ := parseDate("2026-10-23", "today")
	document := fixtureDatabase()
	document.Entries[0].Indicators.SDKPatterns = []string{"org.example.analytics.*", "org.example.crash.**"}
	if errorsFound := validateFixture(document, nil, today); len(errorsFound) != 0 {
		t.Fatalf("valid terminal wildcards rejected: %v", errorsFound)
	}
}

func TestTrackerIndicatorArraysAreOptionalButNonEmptyWhenPresent(t *testing.T) {
	today, _ := parseDate("2026-10-23", "today")
	domainOnly := fixtureDatabase()
	domainOnly.Entries[0].Indicators.SDKPatterns = nil
	if errorsFound := validateFixture(domainOnly, nil, today); len(errorsFound) != 0 {
		t.Fatalf("domain-only tracker record rejected: %v", errorsFound)
	}

	patternOnly := fixtureDatabase()
	patternOnly.Entries[0].Indicators.Domains = nil
	if errorsFound := validateFixture(patternOnly, nil, today); len(errorsFound) != 0 {
		t.Fatalf("SDK-pattern-only tracker record rejected: %v", errorsFound)
	}

	emptyPresent := fixtureDatabase()
	emptyPresent.Entries[0].Indicators.Domains = []string{}
	if errorsFound := validateFixture(emptyPresent, nil, today); len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "domains must be a non-empty array") {
		t.Fatalf("explicitly empty domains array was not rejected: %v", errorsFound)
	}

	encoded, err := json.Marshal(domainOnly)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTempFile(t, "domain-only.json", string(encoded))
	decoded, err := readTrackerDatabase(path)
	if err != nil {
		t.Fatalf("domain-only JSON did not decode: %v", err)
	}
	if errorsFound := validateFixture(decoded, nil, today); len(errorsFound) != 0 {
		t.Fatalf("domain-only JSON rejected after decode: %v", errorsFound)
	}

	encoded, err = json.Marshal(fixtureDatabase())
	if err != nil {
		t.Fatal(err)
	}
	emptyJSON := strings.Replace(string(encoded), "\"domains\":[\"metrics.example.org\"]", "\"domains\":[]", 1)
	path = writeTempFile(t, "empty-domain-array.json", emptyJSON)
	decoded, err = readTrackerDatabase(path)
	if err != nil {
		t.Fatalf("explicit empty array should remain a schema validation error, not JSON syntax failure: %v", err)
	}
	if errorsFound := validateFixture(decoded, nil, today); len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "domains must be a non-empty array") {
		t.Fatalf("explicit empty domains array not rejected after decode: %v", errorsFound)
	}
}

func TestValidateTrackerCLIRejectsExplicitNonpositiveAgeLimit(t *testing.T) {
	data, err := json.Marshal(fixtureDatabase())
	if err != nil {
		t.Fatal(err)
	}
	path := writeTempFile(t, "tracker.json", string(data))
	if code := runValidateTracker([]string{"--file", path}); code != 0 {
		t.Fatalf("default CLI validation failed with code %d", code)
	}
	for _, value := range []string{"0", "-1"} {
		if code := runValidateTracker([]string{"--file", path, "--max-age-days", value}); code != 2 {
			t.Errorf("explicit max-age-days %s returned %d, want usage-error exit code 2", value, code)
		}
	}
}

func TestTrackerFreshnessGate(t *testing.T) {
	today, _ := parseDate("2026-10-23", "today")
	limit := 180
	document := fixtureDatabase()
	document.Entries[0].LastVerified = "2026-10-20"
	if errorsFound := validateFixture(document, &limit, today); len(errorsFound) != 0 {
		t.Fatalf("fresh evidence rejected: %v", errorsFound)
	}
	document.Entries[0].LastVerified = "2026-04-01"
	errorsFound := validateFixture(document, &limit, today)
	if len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "evidence review is required") {
		t.Fatalf("stale evidence not rejected: %v", errorsFound)
	}
	document.Entries[0].LastVerified = "2026-10-24"
	errorsFound = validateFixture(document, &limit, today)
	if len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "must not be in the future") {
		t.Fatalf("future-dated evidence not rejected: %v", errorsFound)
	}
	zero := 0
	if errorsFound = validateFixture(fixtureDatabase(), &zero, today); len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "positive integer") {
		t.Fatalf("zero freshness window not rejected: %v", errorsFound)
	}
}

func TestRepositoryTrackerCatalogAndEvidenceClassifications(t *testing.T) {
	path := filepath.Join(repoRoot(), "shared", "tracker-db", "signatures.json")
	document, err := readTrackerDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Entries) < 15 {
		t.Fatalf("catalog unexpectedly small: %d records", len(document.Entries))
	}
	today := time.Now().UTC()
	limit := 180
	if errorsFound := validateTrackerDatabase(document, &limit, today); len(errorsFound) != 0 {
		t.Fatalf("repository catalog fails schema/freshness: %v", errorsFound)
	}
	byID := make(map[string]trackerEntry, len(document.Entries))
	for _, entry := range document.Entries {
		byID[entry.ID] = entry
	}
	expected := map[string]struct {
		domain string
		evidencePrefix string
	}{
		"microsoft-clarity-collection": {"www.clarity.ms", "https://learn.microsoft.com/"},
		"posthog-hosted-event-capture": {"us.i.posthog.com", "https://posthog.com/docs/"},
		"google-ads-measurement-endpoints": {"googleadservices.com", "https://developers.google.com/"},
		"pinterest-tag-conversion": {"ct.pinterest.com", "https://developers.pinterest.com/docs/"},
		"amplitude-event-ingestion": {"api2.amplitude.com", "https://www.amplitude.com/docs/"},
		"segment-event-ingestion": {"api.segment.io", "https://segment.com/"},
		"mixpanel-event-ingestion": {"api.mixpanel.com", "https://developer.mixpanel.com/reference/"},
		"adjust-attribution-links": {"app.adjust.com", "https://help.adjust.com/"},
		"bugsnag-crash-reporting": {"notify.bugsnag.com", "https://docs.bugsnag.com/"},
	}
	for id, check := range expected {
		entry, found := byID[id]
		if !found {
			t.Errorf("missing curated record %s", id)
			continue
		}
		if !contains(entry.Indicators.Domains, check.domain) {
			t.Errorf("%s does not contain expected domain %s", id, check.domain)
		}
		if entry.Status != "active" {
			t.Errorf("%s status = %s, want active", id, entry.Status)
		}
		hasEvidence := false
		for _, source := range entry.Evidence {
			if strings.HasPrefix(source.URL, check.evidencePrefix) {
				hasEvidence = true
				break
			}
		}
		if !hasEvidence {
			t.Errorf("%s lacks expected official evidence prefix %s", id, check.evidencePrefix)
		}
	}
	for _, id := range []string{"sentry-event-ingestion", "branch-mobile-linking", "appsflyer-mobile-attribution", "google-floodlight-doubleclick"} {
		entry, found := byID[id]
		if !found {
			t.Errorf("missing review-only record %s", id)
			continue
		}
		if entry.Status != "review" || entry.Confidence != "medium" {
			t.Errorf("%s should remain medium-confidence review-only; got %s/%s", id, entry.Confidence, entry.Status)
		}
	}
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func TestReviewReportReviewStatesAndOutput(t *testing.T) {
	today, _ := parseDate("2026-10-23", "today")
	document := trackerDatabase{Entries: []trackerEntry{
		{ID: "current", Name: "Current", Status: "active", Confidence: "high", LastVerified: "2026-10-01", Evidence: []trackerEvidence{{URL: "https://docs.example.org"}}},
		{ID: "soon", Name: "Soon", Status: "review", Confidence: "medium", LastVerified: "2026-05-15", Evidence: []trackerEvidence{{URL: "https://docs.example.org"}}},
		{ID: "old", Name: "Old", Status: "retired", Confidence: "low", LastVerified: "2026-01-01", Evidence: []trackerEvidence{{URL: "https://docs.example.org"}}},
		{ID: "future", Name: "Future", Status: "active", Confidence: "high", LastVerified: "2026-10-24", Evidence: []trackerEvidence{{URL: "https://docs.example.org"}}},
	}}
	report := buildReviewReport(document, today, 180, 30)
	states := make(map[string]string)
	for _, entry := range report.Entries {
		states[entry.ID] = entry.ReviewState
	}
	if states["current"] != "current" || states["soon"] != "due_soon" || states["old"] != "overdue" || states["future"] != "invalid_future_date" {
		t.Fatalf("unexpected review states: %#v", states)
	}
	if report.Counts["overdue"] != 1 || report.Counts["due_soon"] != 1 || report.Counts["invalid_future_date"] != 1 {
		t.Fatalf("unexpected report counts: %#v", report.Counts)
	}
	markdown := renderMarkdown(report)
	if !strings.Contains(markdown, "**Limit:**") || !strings.Contains(markdown, "`old`") {
		t.Fatalf("markdown report missing expected limitations or entry row: %s", markdown)
	}
	jsonReport, err := json.Marshal(report)
	if err != nil || !strings.Contains(string(jsonReport), "evidence_urls") || !strings.Contains(string(jsonReport), "limitation") {
		t.Fatalf("JSON report missing required data: %s (%v)", jsonReport, err)
	}
}

func TestRepositoryTrackerReportIncludesLimitationsAndEntries(t *testing.T) {
	path := filepath.Join(repoRoot(), "shared", "tracker-db", "signatures.json")
	document, err := readTrackerDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if validationErrors := validateTrackerDatabase(document, nil, time.Now().UTC()); len(validationErrors) != 0 {
		t.Fatal(validationErrors)
	}
	today, _ := parseDate("2026-10-23", "today")
	report := buildReviewReport(document, today, 180, 30)
	if len(report.Entries) < 15 || !strings.Contains(report.Limitation, "does not fetch sources") {
		t.Fatalf("report is missing entries or honest limits: %#v", report)
	}
}

func TestBackupManifestRequiresExplicitFalse(t *testing.T) {
	actual := filepath.Join(repoRoot(), "android-app", "app", "src", "main", "AndroidManifest.xml")
	if errorsFound := validateBackupManifest(actual); len(errorsFound) != 0 {
		t.Fatalf("repository manifest rejected: %v", errorsFound)
	}
	tests := []struct {
		name string
		xml string
		want string
	}{
		{"true", `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="true"/></manifest>`, "allowBackup"},
		{"missing attribute", `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:label="PrivaCage"/></manifest>`, "explicitly declare"},
		{"missing application", `<manifest xmlns:android="http://schemas.android.com/apk/res/android"/>`, "<application>"},
		{"multiple applications", `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="false"/><application android:allowBackup="false"/></manifest>`, "exactly one"},
		{"malformed", "<manifest><application>", "XML is invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeTempFile(t, "AndroidManifest.xml", test.xml)
			errorsFound := validateBackupManifest(path)
			if test.name == "malformed" {
				if len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "XML is invalid") {
					t.Fatalf("malformed XML not reported: %v", errorsFound)
				}
				return
			}
			if len(errorsFound) == 0 || !strings.Contains(errorsFound[0], test.want) {
				t.Fatalf("got errors %v; want %q", errorsFound, test.want)
			}
		})
	}
}

func TestAndroidPrivacyManifestAndGradleMarkers(t *testing.T) {
	actual := filepath.Join(repoRoot(), "android-app", "app", "src", "main", "AndroidManifest.xml")
	if errorsFound := validatePrivacyManifest(actual); len(errorsFound) != 0 {
		t.Fatalf("repository manifest rejected: %v", errorsFound)
	}
	if errorsFound := validateAndroidDependencies(filepath.Join(repoRoot(), "android-app")); len(errorsFound) != 0 {
		t.Fatalf("repository Gradle files rejected: %v", errorsFound)
	}

	manifest := `<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/><application android:allowBackup="false"/></manifest>`
	path := writeTempFile(t, "SensitiveManifest.xml", manifest)
	errorsFound := validatePrivacyManifest(path)
	if len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "ACCESS_FINE_LOCATION") {
		t.Fatalf("sensitive permission not rejected: %v", errorsFound)
	}

	directory := t.TempDir()
	gradle := filepath.Join(directory, "app.gradle.kts")
	if err := os.WriteFile(gradle, []byte(`dependencies { implementation("com.google.firebase:firebase-analytics") }`), 0600); err != nil {
		t.Fatal(err)
	}
	errorsFound = validateAndroidDependencies(directory)
	if len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "firebase-analytics") {
		t.Fatalf("known telemetry SDK marker not rejected: %v", errorsFound)
	}
	if errorsFound = validateAndroidDependencies(filepath.Join(directory, "does-not-exist")); len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "does not exist") {
		t.Fatalf("missing Android directory not reported: %v", errorsFound)
	}
}

func TestBackupAndPrivacyValidatorsReportUnreadableFiles(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.xml")
	if errorsFound := validateBackupManifest(missing); len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "cannot read manifest") {
		t.Fatalf("backup validator swallowed missing file: %v", errorsFound)
	}
	if errorsFound := validatePrivacyManifest(missing); len(errorsFound) == 0 || !strings.Contains(errorsFound[0], "cannot read manifest") {
		t.Fatalf("privacy validator swallowed missing file: %v", errorsFound)
	}
}
