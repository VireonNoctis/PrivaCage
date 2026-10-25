package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func appAlternativeFixture() appAlternativeCatalog {
	return appAlternativeCatalog{
		SchemaVersion: 1,
		UpdatedAt: "2026-10-25",
		Alternatives: []appAlternativeRecord{{
			ID: "gmail-proton-mail",
			Replaces: "Gmail",
			Category: "Email",
			Name: "Proton Mail",
			Summary: "Privacy-oriented email client.",
			Tradeoffs: "Email metadata still exists.",
			EvidenceURL: "https://proton.me/mail/security",
			Sources: []appAlternativeSource{{
				ID: "play", Label: "Google Play",
				URL: "https://play.google.com/store/apps/details?id=ch.protonmail.android",
			}},
		}},
	}
}

func TestAppAlternativeCatalogAcceptsValidRecord(t *testing.T) {
	catalog := appAlternativeFixture()
	if problems := validateAppAlternativeCatalog(catalog, time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)); len(problems) != 0 {
		t.Fatalf("valid fixture rejected: %v", problems)
	}
}

func TestBundledAppAlternativeCatalogPassesItsOwnValidator(t *testing.T) {
	catalog, err := readAppAlternativeCatalog(defaultAppAlternativeCatalogPath())
	if err != nil {
		t.Fatalf("bundled app-alternative catalogue rejected: %v", err)
	}
	if len(catalog.Alternatives) < 20 {
		t.Fatalf("catalogue unexpectedly small: got %d records", len(catalog.Alternatives))
	}
}

func TestAppAlternativeCatalogRejectsInvalidRecords(t *testing.T) {
	tests := []struct {
		name string
		mutate func(*appAlternativeCatalog)
		want string
	}{
		{
			name: "duplicate record ID",
			mutate: func(c *appAlternativeCatalog) { c.Alternatives = append(c.Alternatives, c.Alternatives[0]) },
			want: "duplicate alternative id",
		},
		{
			name: "plain HTTP",
			mutate: func(c *appAlternativeCatalog) { c.Alternatives[0].Sources[0].URL = "http://play.google.com/store/apps" },
			want: "must use HTTPS",
		},
		{
			name: "unapproved host",
			mutate: func(c *appAlternativeCatalog) { c.Alternatives[0].Sources[0].URL = "https://play.google.com.attacker.invalid/store/apps" },
			want: "not on the reviewed HTTPS allowlist",
		},
		{
			name: "URL user info",
			mutate: func(c *appAlternativeCatalog) { c.Alternatives[0].Sources[0].URL = "https://user:pass@play.google.com/store/apps" },
			want: "must not contain credentials",
		},
		{
			name: "unexpected port",
			mutate: func(c *appAlternativeCatalog) { c.Alternatives[0].EvidenceURL = "https://proton.me:8443/mail/security" },
			want: "port must be omitted or 443",
		},
		{
			name: "unknown source type",
			mutate: func(c *appAlternativeCatalog) { c.Alternatives[0].Sources[0].ID = "arbitrary" },
			want: "not a supported source type",
		},
		{
			name: "duplicate source type",
			mutate: func(c *appAlternativeCatalog) { c.Alternatives[0].Sources = append(c.Alternatives[0].Sources, c.Alternatives[0].Sources[0]) },
			want: "duplicates source type",
		},
		{
			name: "future update date",
			mutate: func(c *appAlternativeCatalog) { c.UpdatedAt = "2026-10-26" },
			want: "must not be in the future",
		},
		{
			name: "empty evidence URL",
			mutate: func(c *appAlternativeCatalog) { c.Alternatives[0].EvidenceURL = "" },
			want: "must be non-empty",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := appAlternativeFixture()
			test.mutate(&catalog)
			problems := validateAppAlternativeCatalog(catalog, time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC))
			if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), test.want) {
				t.Fatalf("got problems %v, want one containing %q", problems, test.want)
			}
		})
	}
}

func TestAppAlternativeJSONRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	bytes, err := json.Marshal(appAlternativeFixture())
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(bytes), "\"name\":\"Proton Mail\"", "\"name\":\"Proton Mail\",\"installer_command\":\"fake\"", 1)
	path := writeTempFile(t, "app-alternatives-unknown.json", unknown)
	if _, err := readAppAlternativeCatalog(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field was not rejected: %v", err)
	}

	path = writeTempFile(t, "app-alternatives-trailing.json", string(bytes)+" {}")
	if _, err := readAppAlternativeCatalog(path); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("trailing JSON value was not rejected: %v", err)
	}
}

func TestAppAlternativeCatalogRejectsOversizedInput(t *testing.T) {
	path := writeTempFile(t, "app-alternatives-large.json", strings.Repeat(" ", maxAppAlternativeCatalogBytes+1))
	if _, err := readAppAlternativeCatalog(path); err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("oversized catalogue was not rejected: %v", err)
	}
}

func TestRunValidateAppAlternativesCommandAcceptsExplicitFile(t *testing.T) {
	data, err := json.Marshal(appAlternativeFixture())
	if err != nil {
		t.Fatal(err)
	}
	path := writeTempFile(t, "app-alternatives.json", string(data))
	if code := runValidateAppAlternatives([]string{"-file", path}); code != 0 {
		t.Fatalf("valid catalogue exited with %d", code)
	}
	if code := runValidateAppAlternatives([]string{"unexpected"}); code != 2 {
		t.Fatalf("unexpected positional argument exited with %d", code)
	}
}
