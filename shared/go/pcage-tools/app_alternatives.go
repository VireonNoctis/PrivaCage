package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxAppAlternativeCatalogBytes = 512 * 1024

var appAlternativeSourceIDs = map[string]struct{}{
	"play": {},
	"fdroid": {},
	"official": {},
	"github": {},
	"gitlab": {},
}

var appAlternativeHosts = map[string]struct{}{
	"anysoftkeyboard.github.io": {},
	"bitwarden.com": {},
	"brave.com": {},
	"duckduckgo.com": {},
	"ente.io": {},
	"f-droid.org": {},
	"getaegis.app": {},
	"github.com": {},
	"gitlab.com": {},
	"jitsi.org": {},
	"joplinapp.org": {},
	"newpipe.net": {},
	"nextcloud.com": {},
	"organicmaps.app": {},
	"osmand.net": {},
	"play.google.com": {},
	"proton.me": {},
	"signal.org": {},
	"simplex.chat": {},
	"support.mozilla.org": {},
	"www.collaboraoffice.com": {},
	"www.fossify.org": {},
	"www.keepassdx.com": {},
	"www.mozilla.org": {},
	"www.thunderbird.net": {},
}

var appAlternativeIDPattern = regexp.MustCompile("^[a-z0-9]+(-[a-z0-9]+)*$")
var appAlternativePackagePattern = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+$")

type appAlternativeCatalog struct {
	SchemaVersion int                    `json:"schema_version"`
	UpdatedAt     string                 `json:"updated_at"`
	Alternatives  []appAlternativeRecord `json:"alternatives"`
}

type appAlternativeRecord struct {
	ID          string                 `json:"id"`
	PackageName string                 `json:"package_name"`
	Replaces    string                 `json:"replaces"`
	Category    string                 `json:"category"`
	Name        string                 `json:"name"`
	Summary     string                 `json:"summary"`
	Tradeoffs   string                 `json:"tradeoffs"`
	EvidenceURL string                 `json:"evidence_url"`
	Sources     []appAlternativeSource `json:"sources"`
}

type appAlternativeSource struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	URL   string `json:"url"`
}

func (catalog *appAlternativeCatalog) UnmarshalJSON(data []byte) error {
	if err := rejectUnknownJSONFields(data, []string{"schema_version", "updated_at", "alternatives"}, "app-alternative catalogue"); err != nil {
		return err
	}
	type wire appAlternativeCatalog
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*catalog = appAlternativeCatalog(decoded)
	return nil
}

func (record *appAlternativeRecord) UnmarshalJSON(data []byte) error {
	if err := rejectUnknownJSONFields(data, []string{"id", "package_name", "replaces", "category", "name", "summary", "tradeoffs", "evidence_url", "sources"}, "app-alternative record"); err != nil {
		return err
	}
	type wire appAlternativeRecord
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*record = appAlternativeRecord(decoded)
	return nil
}

func (source *appAlternativeSource) UnmarshalJSON(data []byte) error {
	if err := rejectUnknownJSONFields(data, []string{"id", "label", "url"}, "app-alternative source"); err != nil {
		return err
	}
	type wire appAlternativeSource
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*source = appAlternativeSource(decoded)
	return nil
}

func defaultAppAlternativeCatalogPath() string {
	return filepath.Join(repoRoot(), "shared", "app-alternatives", "catalog.json")
}

func readAppAlternativeCatalog(path string) (appAlternativeCatalog, error) {
	file, err := os.Open(path)
	if err != nil {
		return appAlternativeCatalog{}, fmt.Errorf("open app-alternative catalogue: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxAppAlternativeCatalogBytes+1))
	if err != nil {
		return appAlternativeCatalog{}, fmt.Errorf("read app-alternative catalogue: %w", err)
	}
	if len(data) == 0 {
		return appAlternativeCatalog{}, errors.New("app-alternative catalogue is empty")
	}
	if len(data) > maxAppAlternativeCatalogBytes {
		return appAlternativeCatalog{}, fmt.Errorf("app-alternative catalogue exceeds the %d-byte safety limit", maxAppAlternativeCatalogBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var catalog appAlternativeCatalog
	if err := decoder.Decode(&catalog); err != nil {
		return appAlternativeCatalog{}, fmt.Errorf("decode app-alternative catalogue: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return appAlternativeCatalog{}, errors.New("app-alternative catalogue contains multiple JSON values")
		}
		return appAlternativeCatalog{}, fmt.Errorf("app-alternative catalogue has trailing data: %w", err)
	}
	if problems := validateAppAlternativeCatalog(catalog, todayDate()); len(problems) > 0 {
		return appAlternativeCatalog{}, errors.New(strings.Join(problems, "; "))
	}
	return catalog, nil
}

func validateAppAlternativeCatalog(catalog appAlternativeCatalog, today time.Time) []string {
	problems := make([]string, 0)
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	if catalog.SchemaVersion != 1 {
		add("schema_version must equal 1")
	}
	updatedAt, err := parseDate(catalog.UpdatedAt, "updated_at")
	if err != nil {
		add("updated_at must be a valid canonical YYYY-MM-DD date")
	} else if updatedAt.After(today) {
		add("updated_at must not be in the future")
	}
	if len(catalog.Alternatives) == 0 || len(catalog.Alternatives) > 200 {
		add("alternatives must contain between 1 and 200 records")
	}

	seenIDs := make(map[string]struct{}, len(catalog.Alternatives))
	for index, record := range catalog.Alternatives {
		context := fmt.Sprintf("alternatives[%d]", index)
		if strings.TrimSpace(record.ID) == "" || !appAlternativeIDPattern.MatchString(record.ID) {
			add("%s.id must be lowercase kebab-case", context)
		}
		if _, exists := seenIDs[record.ID]; exists {
			add("duplicate alternative id %q", record.ID)
		}
		seenIDs[record.ID] = struct{}{}
		requireAlternativeText := func(field, value string, maxLength int) {
			if value == "" || strings.TrimSpace(value) != value || len(value) > maxLength || strings.ContainsRune(value, '\x00') {
				add("%s.%s must be non-empty trimmed text within %d bytes", context, field, maxLength)
			}
		}
		requireAlternativeText("package_name", record.PackageName, 255)
		if !appAlternativePackagePattern.MatchString(record.PackageName) {
			add("%s.package_name must be a valid dotted Android package name", context)
		}
		requireAlternativeText("replaces", record.Replaces, 100)
		requireAlternativeText("category", record.Category, 60)
		requireAlternativeText("name", record.Name, 100)
		requireAlternativeText("summary", record.Summary, 600)
		requireAlternativeText("tradeoffs", record.Tradeoffs, 700)
		if err := validateTrustedAlternativeURL(record.EvidenceURL); err != nil {
			add("%s.evidence_url: %v", context, err)
		}
		if len(record.Sources) == 0 || len(record.Sources) > 4 {
			add("%s.sources must contain between 1 and 4 choices", context)
		}
		seenSources := make(map[string]struct{}, len(record.Sources))
		for sourceIndex, source := range record.Sources {
			sourceContext := fmt.Sprintf("%s.sources[%d]", context, sourceIndex)
			if _, supported := appAlternativeSourceIDs[source.ID]; !supported {
				add("%s.id is not a supported source type", sourceContext)
			}
			if _, exists := seenSources[source.ID]; exists {
				add("%s duplicates source type %q", sourceContext, source.ID)
			}
			seenSources[source.ID] = struct{}{}
			if source.Label == "" || strings.TrimSpace(source.Label) != source.Label || len(source.Label) > 80 {
				add("%s.label must be non-empty trimmed text no longer than 80 bytes", sourceContext)
			}
			if err := validateTrustedAlternativeURL(source.URL); err != nil {
				add("%s.url: %v", sourceContext, err)
			}
		}
	}
	sort.Strings(problems)
	return problems
}

func validateTrustedAlternativeURL(value string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\\ \t\r\n") {
		return errors.New("URL must be non-empty and contain no whitespace or backslashes")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("URL is invalid: %w", err)
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Scheme != "https" || host == "" {
		return errors.New("URL must use HTTPS and include a host")
	}
	if _, trusted := appAlternativeHosts[host]; !trusted {
		return fmt.Errorf("host %q is not on the reviewed HTTPS allowlist", host)
	}
	if parsed.User != nil {
		return errors.New("URL must not contain credentials")
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return errors.New("URL port must be omitted or 443")
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		return errors.New("URL must not contain a fragment")
	}
	if parsed.Opaque != "" || parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") {
		return errors.New("URL must be an absolute HTTPS URL with a path")
	}
	return nil
}

func runValidateAppAlternatives(args []string) int {
	flags := newFlagSet("validate-app-alternatives")
	path := flags.String("file", defaultAppAlternativeCatalogPath(), "path to app-alternative catalogue JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: unexpected positional arguments")
		return 2
	}
	catalog, err := readAppAlternativeCatalog(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	fmt.Printf("OK: %s passed app-alternative validation (%d records; schema v%d)\n", *path, len(catalog.Alternatives), catalog.SchemaVersion)
	return 0
}


type appAlternativeFreshnessEntry struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	EvidenceURL            string `json:"evidence_url"`
	CatalogUpdatedAt       string `json:"catalog_updated_at"`
	CatalogAgeDays         int    `json:"catalog_age_days"`
	CatalogReviewState     string `json:"catalog_review_state"`
	SourceReviewDateKnown  bool   `json:"source_review_date_known"`
	SourceReviewLimitation string `json:"source_review_limitation"`
}

type appAlternativeFreshnessReport struct {
	GeneratedAt        string                         `json:"generated_at"`
	CatalogUpdatedAt   string                         `json:"catalog_updated_at"`
	MaxAgeDays         int                            `json:"max_age_days"`
	DueSoonDays        int                            `json:"due_soon_days"`
	Counts             map[string]int                 `json:"counts"`
	Entries            []appAlternativeFreshnessEntry `json:"entries"`
	Limitation         string                         `json:"limitation"`
}

func buildAppAlternativeFreshnessReport(
	catalog appAlternativeCatalog,
	today time.Time,
	maxAgeDays int,
	dueSoonDays int,
) (appAlternativeFreshnessReport, bool) {
	updatedAt, _ := time.Parse(dateLayout, catalog.UpdatedAt) // Schema validation has already checked this date.
	ageDays := int(today.Sub(updatedAt).Hours() / 24)
	state := "current"
	if updatedAt.After(today) {
		state = "future-dated"
	} else if ageDays > maxAgeDays {
		state = "stale"
	} else if dueSoonDays > 0 && ageDays >= maxAgeDays-dueSoonDays {
		state = "due-soon"
	}

	report := appAlternativeFreshnessReport{
		GeneratedAt:      today.Format(dateLayout),
		CatalogUpdatedAt: catalog.UpdatedAt,
		MaxAgeDays:       maxAgeDays,
		DueSoonDays:      dueSoonDays,
		Counts:            map[string]int{"current": 0, "due-soon": 0, "stale": 0, "future-dated": 0},
		Entries:           make([]appAlternativeFreshnessEntry, 0, len(catalog.Alternatives)),
		Limitation:        "Freshness here means catalogue updated_at only. Schema v1 has no per-entry source review date, so this report cannot claim individual evidence URLs or trade-offs were re-checked on that date.",
	}
	report.Counts[state] = len(catalog.Alternatives)
	for _, record := range catalog.Alternatives {
		report.Entries = append(report.Entries, appAlternativeFreshnessEntry{
			ID:                     record.ID,
			Name:                   record.Name,
			EvidenceURL:            record.EvidenceURL,
			CatalogUpdatedAt:       catalog.UpdatedAt,
			CatalogAgeDays:         ageDays,
			CatalogReviewState:     state,
			SourceReviewDateKnown:  false,
			SourceReviewLimitation: "No per-entry source-review date exists in schema v1.",
		})
	}
	sort.Slice(report.Entries, func(i, j int) bool {
		return report.Entries[i].ID < report.Entries[j].ID
	})
	return report, state == "stale" || state == "future-dated"
}

func runAppAlternativeReport(args []string) int {
	flags := newFlagSet("app-alternatives-report")
	path := flags.String("file", defaultAppAlternativeCatalogPath(), "path to app-alternative catalogue JSON")
	maxAgeDays := flags.Int("max-age-days", 180, "mark the catalogue stale after this many days")
	dueSoonDays := flags.Int("due-soon-days", 30, "mark catalogue review due soon within this many days")
	todayText := flags.String("today", todayDate().Format(dateLayout), "override date (YYYY-MM-DD), mainly for tests")
	format := flags.String("format", "markdown", "output format: markdown or json")
	failStale := flags.Bool("fail-stale", false, "return exit code 1 when the catalogue date is stale or future-dated")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "ERROR: unexpected positional arguments")
		return 2
	}
	if *maxAgeDays <= 0 || *dueSoonDays < 0 {
		fmt.Fprintln(os.Stderr, "ERROR: max-age-days must be positive and due-soon-days must be non-negative")
		return 2
	}
	if *format != "markdown" && *format != "json" {
		fmt.Fprintln(os.Stderr, "ERROR: format must be markdown or json")
		return 2
	}
	today, err := parseDate(*todayText, "today")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: today must be canonical YYYY-MM-DD")
		return 2
	}
	catalog, err := readAppAlternativeCatalog(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	report, stale := buildAppAlternativeFreshnessReport(catalog, today, *maxAgeDays, *dueSoonDays)
	if *format == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: encode report: %v\n", err)
			return 1
		}
	} else {
		fmt.Printf("# App-alternative catalogue freshness\n\n")
		fmt.Printf("- Generated: %s\n- Catalogue updated: %s\n- Age: %d days (limit %d)\n", report.GeneratedAt, report.CatalogUpdatedAt, report.Entries[0].CatalogAgeDays, report.MaxAgeDays)
		fmt.Printf("- Status counts: current=%d, due-soon=%d, stale=%d, future-dated=%d\n\n", report.Counts["current"], report.Counts["due-soon"], report.Counts["stale"], report.Counts["future-dated"])
		fmt.Printf("| ID | Alternative | Catalogue state | Evidence URL |\n|---|---|---|---|\n")
		for _, entry := range report.Entries {
			fmt.Printf("| %s | %s | %s | %s |\n", entry.ID, entry.Name, entry.CatalogReviewState, entry.EvidenceURL)
		}
		fmt.Printf("\n**Limitation:** %s\n", report.Limitation)
	}
	if stale && *failStale {
		fmt.Fprintln(os.Stderr, "ERROR: app-alternative catalogue updated_at is stale or future-dated")
		return 1
	}
	return 0
}
