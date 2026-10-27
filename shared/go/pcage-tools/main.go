package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	dateLayout = "2006-01-02"
)

var (
	idPattern = regexp.MustCompile("^[a-z0-9]+(-[a-z0-9]+)*$")
	domainLabelPattern = regexp.MustCompile("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
	sdkPattern = regexp.MustCompile("^[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+(\\.(\\*|\\*\\*))?$")
	sensitivePermissions = map[string]struct{}{
		"android.permission.ACCESS_BACKGROUND_LOCATION": {},
		"android.permission.ACCESS_COARSE_LOCATION": {},
		"android.permission.ACCESS_FINE_LOCATION": {},
		"android.permission.ACTIVITY_RECOGNITION": {},
		"android.permission.BLUETOOTH_SCAN": {},
		"android.permission.BODY_SENSORS": {},
		"android.permission.CAMERA": {},
		"android.permission.NEARBY_WIFI_DEVICES": {},
		"android.permission.QUERY_ALL_PACKAGES": {},
		"android.permission.READ_CALL_LOG": {},
		"android.permission.READ_CONTACTS": {},
		"android.permission.READ_PHONE_NUMBERS": {},
		"android.permission.READ_PHONE_STATE": {},
		"android.permission.READ_SMS": {},
		"android.permission.RECORD_AUDIO": {},
	}
	telemetryMarkers = []string{
		"firebase-analytics",
		"firebase-crashlytics",
		"play-services-ads",
		"sentry-android",
		"bugsnag",
		"appsflyer",
		"adjust-android",
		"mixpanel",
		"amplitude-android",
		"segment-analytics",
	}
)

type trackerDatabase struct {
	SchemaVersion int             `json:"schema_version"`
	UpdatedAt     string          `json:"updated_at"`
	Entries       []trackerEntry  `json:"entries"`
}

type trackerEntry struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Indicators  trackerIndicators `json:"indicators"`
	Confidence  string            `json:"confidence"`
	Status      string            `json:"status"`
	LastVerified string           `json:"last_verified"`
	Evidence    []trackerEvidence `json:"evidence"`
}

type trackerIndicators struct {
	Domains         []string `json:"domains,omitempty"`
	SDKPatterns     []string `json:"sdk_patterns,omitempty"`
	domainsPresent  bool
	sdkPatternsPresent bool
}

func (indicators *trackerIndicators) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name := range fields {
		if name != "domains" && name != "sdk_patterns" {
			return fmt.Errorf("unsupported indicators field %q", name)
		}
	}
	if value, exists := fields["domains"]; exists {
		indicators.domainsPresent = true
		if err := json.Unmarshal(value, &indicators.Domains); err != nil {
			return fmt.Errorf("indicators.domains must be an array of strings: %w", err)
		}
	}
	if value, exists := fields["sdk_patterns"]; exists {
		indicators.sdkPatternsPresent = true
		if err := json.Unmarshal(value, &indicators.SDKPatterns); err != nil {
			return fmt.Errorf("indicators.sdk_patterns must be an array of strings: %w", err)
		}
	}
	return nil
}

type trackerEvidence struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

func rejectUnknownJSONFields(data []byte, allowed []string, context string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	allowedFields := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedFields[name] = struct{}{}
	}
	for name := range fields {
		if _, ok := allowedFields[name]; !ok {
			return fmt.Errorf("unknown field %q in %s", name, context)
		}
	}
	return nil
}

func (database *trackerDatabase) UnmarshalJSON(data []byte) error {
	if err := rejectUnknownJSONFields(data, []string{"schema_version", "updated_at", "entries"}, "tracker database"); err != nil {
		return err
	}
	type wire trackerDatabase
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*database = trackerDatabase(decoded)
	return nil
}

func (entry *trackerEntry) UnmarshalJSON(data []byte) error {
	if err := rejectUnknownJSONFields(data, []string{"id", "name", "category", "indicators", "confidence", "status", "last_verified", "evidence"}, "tracker entry"); err != nil {
		return err
	}
	type wire trackerEntry
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*entry = trackerEntry(decoded)
	return nil
}

func (evidence *trackerEvidence) UnmarshalJSON(data []byte) error {
	if err := rejectUnknownJSONFields(data, []string{"url", "description"}, "tracker evidence"); err != nil {
		return err
	}
	type wire trackerEvidence
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*evidence = trackerEvidence(decoded)
	return nil
}

type reviewEntry struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	Confidence   string   `json:"confidence"`
	LastVerified string   `json:"last_verified"`
	AgeDays      int      `json:"age_days"`
	ReviewDue    string   `json:"review_due"`
	DaysUntilDue int      `json:"days_until_due"`
	ReviewState  string   `json:"review_state"`
	EvidenceURLs []string `json:"evidence_urls"`
}

type reviewReport struct {
	GeneratedAt       string        `json:"generated_at"`
	ReviewIntervalDays int          `json:"review_interval_days"`
	DueSoonDays       int           `json:"due_soon_days"`
	Counts            map[string]int `json:"counts"`
	Entries           []reviewEntry `json:"entries"`
	Limitation        string        `json:"limitation"`
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "validate-tracker":
		return runValidateTracker(args[1:])
	case "validate-app-alternatives":
		return runValidateAppAlternatives(args[1:])
	case "app-alternatives-report":
		return runAppAlternativeReport(args[1:])
	case "tracker-report":
		return runTrackerReport(args[1:])
	case "validate-android-backup":
		return runValidateAndroidBackup(args[1:])
	case "validate-android-privacy":
		return runValidateAndroidPrivacy(args[1:])
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "ERROR: unknown command %q\n", args[0])
		printUsage(os.Stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "PrivaCage repository privacy tools")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  validate-tracker         Validate tracker schema and optionally evidence freshness")
	fmt.Fprintln(w, "  validate-app-alternatives Validate the curated alternative-app catalogue and source URLs")
	fmt.Fprintln(w, "  app-alternatives-report   Report catalogue freshness and affected record IDs")
	fmt.Fprintln(w, "  tracker-report           Generate the local evidence review report")
	fmt.Fprintln(w, "  validate-android-backup  Check the declared Android backup posture")
	fmt.Fprintln(w, "  validate-android-privacy Check sensitive permissions and known telemetry dependency markers")
}

func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	return flags
}

func repoRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	for path := cwd; ; path = filepath.Dir(path) {
		if isRepoRoot(path) {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
	}
	return cwd
}

func isRepoRoot(path string) bool {
	_, err := os.Stat(filepath.Join(path, "shared", "tracker-db", "signatures.json"))
	return err == nil
}

func defaultTrackerPath() string {
	return filepath.Join(repoRoot(), "shared", "tracker-db", "signatures.json")
}

func defaultManifestPath() string {
	return filepath.Join(repoRoot(), "android-app", "app", "src", "main", "AndroidManifest.xml")
}

func defaultAndroidDir() string {
	return filepath.Join(repoRoot(), "android-app")
}

func runValidateTracker(args []string) int {
	flags := newFlagSet("validate-tracker")
	path := flags.String("file", defaultTrackerPath(), "path to tracker database JSON")
	maxAgeDays := flags.Int("max-age-days", 0, "fail if evidence reviews are older than this many days")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: unexpected positional arguments")
		return 2
	}
	maxAgeSpecified := false
	flags.Visit(func(item *flag.Flag) {
		if item.Name == "max-age-days" {
			maxAgeSpecified = true
		}
	})
	if maxAgeSpecified && *maxAgeDays <= 0 {
		fmt.Fprintln(os.Stderr, "ERROR: max-age-days must be a positive integer")
		return 2
	}
	document, err := readTrackerDatabase(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 2
	}
	var ageLimit *int
	if maxAgeSpecified {
		ageLimit = maxAgeDays
	}
	errorsFound := validateTrackerDatabase(document, ageLimit, todayDate())
	if len(errorsFound) > 0 {
		for _, validationErr := range errorsFound {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", validationErr)
		}
		return 1
	}
	fmt.Printf("OK: %s passed tracker schema validation\n", *path)
	return 0
}

func runTrackerReport(args []string) int {
	flags := newFlagSet("tracker-report")
	path := flags.String("file", defaultTrackerPath(), "path to tracker database JSON")
	intervalDays := flags.Int("interval-days", 180, "review interval in days")
	dueSoonDays := flags.Int("due-soon-days", 30, "number of days before due date to flag as due soon")
	todayText := flags.String("today", todayDate().Format(dateLayout), "override date (YYYY-MM-DD), mainly for tests")
	format := flags.String("format", "markdown", "output format: markdown or json")
	failOverdue := flags.Bool("fail-overdue", false, "return exit code 1 when any entry is overdue or future-dated")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: unexpected positional arguments")
		return 2
	}
	if *intervalDays <= 0 || *dueSoonDays < 0 {
		fmt.Fprintln(os.Stderr, "ERROR: interval-days must be positive and due-soon-days must be non-negative")
		return 2
	}
	if *format != "markdown" && *format != "json" {
		fmt.Fprintln(os.Stderr, "ERROR: format must be markdown or json")
		return 2
	}
	today, err := parseDate(*todayText, "today")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 2
	}
	document, err := readTrackerDatabase(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 2
	}
	if validationErrs := validateTrackerDatabase(document, nil, today); len(validationErrs) > 0 {
		fmt.Fprintf(os.Stderr, "ERROR: invalid tracker database: %s\n", strings.Join(validationErrs, "; "))
		return 2
	}
	report := buildReviewReport(document, today, *intervalDays, *dueSoonDays)
	if *format == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: cannot render JSON report: %v\n", err)
			return 2
		}
	} else {
		fmt.Print(renderMarkdown(report))
	}
	if *failOverdue && (report.Counts["overdue"] > 0 || report.Counts["invalid_future_date"] > 0) {
		return 1
	}
	return 0
}

func runValidateAndroidBackup(args []string) int {
	flags := newFlagSet("validate-android-backup")
	manifest := flags.String("manifest", defaultManifestPath(), "path to AndroidManifest.xml")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: unexpected positional arguments")
		return 2
	}
	errorsFound := validateBackupManifest(*manifest)
	if len(errorsFound) > 0 {
		for _, validationErr := range errorsFound {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", validationErr)
		}
		return 1
	}
	fmt.Printf("OK: %s explicitly disables Android Auto Backup in the source manifest. This static check does not prove OEM/device-to-device transfer behavior.\n", *manifest)
	return 0
}

func runValidateAndroidPrivacy(args []string) int {
	flags := newFlagSet("validate-android-privacy")
	manifest := flags.String("manifest", defaultManifestPath(), "path to AndroidManifest.xml")
	androidDir := flags.String("android-dir", defaultAndroidDir(), "Android project directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: unexpected positional arguments")
		return 2
	}
	errorsFound := validatePrivacyManifest(*manifest)
	errorsFound = append(errorsFound, validateAndroidDependencies(*androidDir)...)
	if len(errorsFound) > 0 {
		for _, validationErr := range errorsFound {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", validationErr)
		}
		return 1
	}
	fmt.Fprintln(os.Stdout, "OK: no unreviewed sensitive permissions or known analytics/ad/crash SDK identifiers were found in the checked Android manifest and Gradle files. This static check does not prove the absence of hand-written telemetry or privileged OS/OEM collection.")
	return 0
}

func readTrackerDatabase(path string) (trackerDatabase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return trackerDatabase{}, fmt.Errorf("cannot read tracker database %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document trackerDatabase
	if err := decoder.Decode(&document); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return trackerDatabase{}, fmt.Errorf("tracker schema fields must be exactly those defined by version 1: %w", err)
		}
		return trackerDatabase{}, fmt.Errorf("invalid JSON in %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return trackerDatabase{}, fmt.Errorf("invalid JSON in %s: multiple JSON values", path)
		}
		return trackerDatabase{}, fmt.Errorf("invalid JSON in %s after tracker document: %w", path, err)
	}
	return document, nil
}

func validateTrackerDatabase(document trackerDatabase, maxAgeDays *int, today time.Time) []string {
	fail := func(message string) []string { return []string{message} }
	if maxAgeDays != nil && *maxAgeDays <= 0 {
		return fail("max_age_days must be a positive integer")
	}
	if document.SchemaVersion != 1 {
		return fail("unsupported schema_version; expected 1")
	}
	if _, err := parseDate(document.UpdatedAt, "updated_at"); err != nil {
		return fail(err.Error())
	}
	if document.Entries == nil {
		return fail("entries must be an array")
	}

	seenIDs := make(map[string]struct{}, len(document.Entries))
	reviewDate := time.Date(today.UTC().Year(), today.UTC().Month(), today.UTC().Day(), 0, 0, 0, 0, time.UTC)
	for index, entry := range document.Entries {
		context := fmt.Sprintf("entries[%d]", index)
		if !idPattern.MatchString(entry.ID) {
			return fail(context + ".id must be lowercase kebab-case")
		}
		if _, found := seenIDs[entry.ID]; found {
			return fail("duplicate id: " + entry.ID)
		}
		seenIDs[entry.ID] = struct{}{}
		for _, field := range []struct {
			name  string
			value string
		}{{"name", entry.Name}, {"category", entry.Category}} {
			if field.value == "" || strings.TrimSpace(field.value) != field.value {
				return fail(context + "." + field.name + " must be non-empty trimmed text")
			}
		}
		if entry.Confidence != "low" && entry.Confidence != "medium" && entry.Confidence != "high" {
			return fail(context + ".confidence must be one of [high low medium]")
		}
		if entry.Status != "active" && entry.Status != "review" && entry.Status != "retired" {
			return fail(context + ".status must be one of [active retired review]")
		}
		lastVerified, err := parseDate(entry.LastVerified, context+".last_verified")
		if err != nil {
			return fail(err.Error())
		}
		if maxAgeDays != nil {
			ageDays := dateDifference(reviewDate, lastVerified)
			if ageDays < 0 {
				return fail(context + ".last_verified must not be in the future")
			}
			if ageDays > *maxAgeDays {
				return fail(fmt.Sprintf("%s.last_verified is %d days old; evidence review is required after %d days", context, ageDays, *maxAgeDays))
			}
		}
		domainsPresent := entry.Indicators.domainsPresent || entry.Indicators.Domains != nil
		patternsPresent := entry.Indicators.sdkPatternsPresent || entry.Indicators.SDKPatterns != nil
		if !domainsPresent && !patternsPresent {
			return fail(context + ".indicators must not be empty and must contain a non-empty domains or sdk_patterns array")
		}
		if domainsPresent {
			if err := validateStringArray(entry.Indicators.Domains, context+".indicators.domains"); err != nil {
				return fail(err.Error())
			}
			for domainIndex, domain := range entry.Indicators.Domains {
				if err := validateDomain(domain, fmt.Sprintf("%s.indicators.domains[%d]", context, domainIndex)); err != nil {
					return fail(err.Error())
				}
			}
		}
		if patternsPresent {
			if err := validateStringArray(entry.Indicators.SDKPatterns, context+".indicators.sdk_patterns"); err != nil {
				return fail(err.Error())
			}
			for patternIndex, pattern := range entry.Indicators.SDKPatterns {
				if !sdkPattern.MatchString(pattern) {
					return fail(fmt.Sprintf("%s.indicators.sdk_patterns[%d] must be a dotted package/class pattern with an optional terminal .* or .** wildcard", context, patternIndex))
				}
			}
		}
		if len(entry.Evidence) == 0 {
			return fail(context + ".evidence must be a non-empty array")
		}
		seenURLs := make(map[string]struct{}, len(entry.Evidence))
		for evidenceIndex, source := range entry.Evidence {
			sourceContext := fmt.Sprintf("%s.evidence[%d]", context, evidenceIndex)
			if err := validateHTTPSURL(source.URL, sourceContext+".url"); err != nil {
				return fail(err.Error())
			}
			if _, found := seenURLs[source.URL]; found {
				return fail(sourceContext + ".url is duplicated")
			}
			seenURLs[source.URL] = struct{}{}
			if source.Description == "" || strings.TrimSpace(source.Description) != source.Description {
				return fail(sourceContext + ".description must be non-empty trimmed text")
			}
		}
	}
	return nil
}

func validateStringArray(values []string, context string) error {
	if len(values) == 0 {
		return fmt.Errorf("%s must be a non-empty array", context)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("%s values must be non-empty trimmed strings", context)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains duplicates", context)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateDomain(value, context string) error {
	if value != strings.ToLower(value) {
		return fmt.Errorf("%s must be lowercase text", context)
	}
	if value == "" || len(value) > 253 {
		return fmt.Errorf("%s must be 1-253 characters", context)
	}
	if strings.HasSuffix(value, ".") {
		return fmt.Errorf("%s must not end with a dot", context)
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%s must be a fully qualified domain", context)
	}
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) {
			return fmt.Errorf("%s is not a valid hostname: %q", context, value)
		}
	}
	return nil
}

func validateHTTPSURL(value, context string) error {
	if value == "" {
		return fmt.Errorf("%s must be a non-empty URL", context)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		if strings.Contains(err.Error(), "port") {
			return fmt.Errorf("%s contains an invalid port", context)
		}
		return fmt.Errorf("%s is not a valid URL: %w", context, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must use HTTPS", context)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("%s must include a hostname", context)
	}
	if parsed.User != nil {
		return fmt.Errorf("%s must not contain credentials", context)
	}
	if portText := parsed.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%s port must be between 1 and 65535", context)
		}
	}
	return nil
}

func parseDate(value, field string) (time.Time, error) {
	parsed, err := time.Parse(dateLayout, value)
	if err != nil || parsed.Format(dateLayout) != value {
		return time.Time{}, fmt.Errorf("%s is not a valid canonical YYYY-MM-DD date: %q", field, value)
	}
	return parsed.UTC(), nil
}

func todayDate() time.Time {
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

func dateDifference(later, earlier time.Time) int {
	later = time.Date(later.UTC().Year(), later.UTC().Month(), later.UTC().Day(), 0, 0, 0, 0, time.UTC)
	earlier = time.Date(earlier.UTC().Year(), earlier.UTC().Month(), earlier.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return int(later.Sub(earlier).Hours() / 24)
}

func buildReviewReport(document trackerDatabase, today time.Time, intervalDays, dueSoonDays int) reviewReport {
	generatedAt := time.Date(today.UTC().Year(), today.UTC().Month(), today.UTC().Day(), 0, 0, 0, 0, time.UTC)
	report := reviewReport{
		GeneratedAt: generatedAt.Format(dateLayout),
		ReviewIntervalDays: intervalDays,
		DueSoonDays: dueSoonDays,
		Counts: map[string]int{
			"current": 0,
			"due_soon": 0,
			"overdue": 0,
			"invalid_future_date": 0,
		},
		Entries: make([]reviewEntry, 0, len(document.Entries)),
		Limitation: "Dates measure catalog review freshness only. This report does not fetch sources or prove their accuracy or current endpoint behavior.",
	}
	for _, entry := range document.Entries {
		lastReview, _ := parseDate(entry.LastVerified, "last_verified")
		dueDate := lastReview.AddDate(0, 0, intervalDays)
		ageDays := dateDifference(generatedAt, lastReview)
		daysUntilDue := dateDifference(dueDate, generatedAt)
		state := "current"
		if ageDays < 0 {
			state = "invalid_future_date"
		} else if daysUntilDue < 0 {
			state = "overdue"
		} else if daysUntilDue <= dueSoonDays {
			state = "due_soon"
		}
		evidenceURLs := make([]string, 0, len(entry.Evidence))
		for _, evidence := range entry.Evidence {
			evidenceURLs = append(evidenceURLs, evidence.URL)
		}
		report.Entries = append(report.Entries, reviewEntry{
			ID: entry.ID,
			Name: entry.Name,
			Status: entry.Status,
			Confidence: entry.Confidence,
			LastVerified: lastReview.Format(dateLayout),
			AgeDays: ageDays,
			ReviewDue: dueDate.Format(dateLayout),
			DaysUntilDue: daysUntilDue,
			ReviewState: state,
			EvidenceURLs: evidenceURLs,
		})
		report.Counts[state]++
	}
	return report
}

func renderMarkdown(report reviewReport) string {
	lines := []string{
		"# Tracker evidence review report",
		"",
		fmt.Sprintf("Generated: %s | Review interval: %d days", report.GeneratedAt, report.ReviewIntervalDays),
		"",
		fmt.Sprintf("- Current: %d", report.Counts["current"]),
		fmt.Sprintf("- Due soon: %d", report.Counts["due_soon"]),
		fmt.Sprintf("- Overdue: %d", report.Counts["overdue"]),
		fmt.Sprintf("- Future-dated / invalid: %d", report.Counts["invalid_future_date"]),
		"",
		"| State | ID | Status | Confidence | Last reviewed | Review due |",
		"|---|---|---|---|---|---|",
	}
	entries := append([]reviewEntry(nil), report.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		left, right := entries[i], entries[j]
		if (left.ReviewState == "overdue") != (right.ReviewState == "overdue") {
			return left.ReviewState == "overdue"
		}
		if left.ReviewDue != right.ReviewDue {
			return left.ReviewDue < right.ReviewDue
		}
		return left.ID < right.ID
	})
	for _, entry := range entries {
		lines = append(lines, fmt.Sprintf("| %s | `%s` | %s | %s | %s | %s |",
			entry.ReviewState, entry.ID, entry.Status, entry.Confidence, entry.LastVerified, entry.ReviewDue))
	}
	lines = append(lines, "", "**Limit:** "+report.Limitation, "")
	return strings.Join(lines, "\n")
}

type backupManifestXML struct {
	XMLName      xml.Name
	Applications []backupApplicationXML `xml:"application"`
}

type backupApplicationXML struct {
	AllowBackup *string `xml:"http://schemas.android.com/apk/res/android allowBackup,attr"`
}

func validateBackupManifest(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot read manifest %s: %v", path, err)}
	}
	var manifest backupManifestXML
	if err := xml.Unmarshal(data, &manifest); err != nil {
		return []string{fmt.Sprintf("manifest XML is invalid in %s: %v", path, err)}
	}
	if manifest.XMLName.Local != "manifest" || manifest.XMLName.Space != "" {
		return []string{"document root must be <manifest>"}
	}
	if len(manifest.Applications) != 1 {
		return []string{"manifest must contain exactly one <application> element"}
	}
	value := manifest.Applications[0].AllowBackup
	if value == nil {
		return []string{`<application> must explicitly declare android:allowBackup="false"`}
	}
	if strings.ToLower(*value) != "false" {
		return []string{`<application> must set android:allowBackup="false" for the current local-data policy`}
	}
	return nil
}

type permissionXML struct {
	Name string `xml:"http://schemas.android.com/apk/res/android name,attr"`
}

type privacyManifestXML struct {
	XMLName              xml.Name
	Permissions          []permissionXML `xml:"uses-permission"`
	PermissionsSDK23      []permissionXML `xml:"uses-permission-sdk-23"`
	PermissionsSDKM       []permissionXML `xml:"uses-permission-sdk-m"`
}

func validatePrivacyManifest(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot read manifest %s: %v", path, err)}
	}
	var manifest privacyManifestXML
	if err := xml.Unmarshal(data, &manifest); err != nil {
		return []string{fmt.Sprintf("manifest XML is invalid in %s: %v", path, err)}
	}
	if manifest.XMLName.Local != "manifest" || manifest.XMLName.Space != "" {
		return []string{"document root must be <manifest>"}
	}
	declared := make(map[string]struct{})
	for _, permission := range append(append(manifest.Permissions, manifest.PermissionsSDK23...), manifest.PermissionsSDKM...) {
		if permission.Name != "" {
			declared[permission.Name] = struct{}{}
		}
	}
	var violations []string
	for permission := range declared {
		if _, sensitive := sensitivePermissions[permission]; sensitive {
			violations = append(violations, "unreviewed sensitive permission declared: "+permission)
		}
	}
	sort.Strings(violations)
	return violations
}

func validateAndroidDependencies(androidDir string) []string {
	info, err := os.Stat(androidDir)
	if err != nil {
		return []string{fmt.Sprintf("Android project directory does not exist: %s", androidDir)}
	}
	if !info.IsDir() {
		return []string{fmt.Sprintf("Android project directory is not a directory: %s", androidDir)}
	}
	var errorsFound []string
	err = filepath.WalkDir(androidDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			errorsFound = append(errorsFound, fmt.Sprintf("cannot inspect Android path %s: %v", path, walkErr))
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".gradle") && !strings.HasSuffix(name, ".gradle.kts") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			errorsFound = append(errorsFound, fmt.Sprintf("cannot read Gradle file %s: %v", path, readErr))
			return nil
		}
		lowerContent := strings.ToLower(string(content))
		for _, marker := range telemetryMarkers {
			if strings.Contains(lowerContent, marker) {
				errorsFound = append(errorsFound, fmt.Sprintf("known telemetry SDK marker %q found in %s", marker, path))
			}
		}
		return nil
	})
	if err != nil {
		errorsFound = append(errorsFound, fmt.Sprintf("cannot scan Android Gradle files under %s: %v", androidDir, err))
	}
	sort.Strings(errorsFound)
	return errorsFound
}
