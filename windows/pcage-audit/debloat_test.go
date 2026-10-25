package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindWin11DebloatScriptFromAuditDirectory(t *testing.T) {
	root := t.TempDir()
	auditDirectory := filepath.Join(root, "windows", "pcage-audit")
	script := filepath.Join(root, "windows", "Win11Debloat", "Win11Debloat.ps1")
	if err := os.MkdirAll(auditDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("Write-Host 'test fixture'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := findWin11DebloatScriptFrom(auditDirectory, filepath.Join(auditDirectory, "pcage-audit.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(script) {
		t.Fatalf("resolved %q, want %q", got, script)
	}
}

func TestFindWin11DebloatScriptReportsMissingSubmodule(t *testing.T) {
	root := t.TempDir()
	_, err := findWin11DebloatScriptFrom(root, filepath.Join(root, "pcage-audit.exe"))
	if err == nil || !strings.Contains(err.Error(), "git submodule update --init --recursive") {
		t.Fatalf("want actionable missing-submodule error, got %v", err)
	}
}

func TestResolveWindowsPowerShellUsesSysnativeForWOW64(t *testing.T) {
	root := filepath.Join("C:", "Windows")
	sysnative := filepath.Join(root, "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe")
	system32 := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	existing := map[string]bool{sysnative: true, system32: true}
	got, err := resolveWindowsPowerShellFrom(root, true, func(path string) bool { return existing[path] })
	if err != nil {
		t.Fatal(err)
	}
	if got != sysnative {
		t.Fatalf("resolved %q, want Sysnative path %q", got, sysnative)
	}
}

func TestResolveWindowsPowerShellRejectsMissingSystemRoot(t *testing.T) {
	_, err := resolveWindowsPowerShellFrom("", false, func(string) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "SystemRoot") {
		t.Fatalf("want missing SystemRoot error, got %v", err)
	}
}
