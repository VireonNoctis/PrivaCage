package test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestWindowsCLIHelpRunsWithoutWindowsPrivileges(t *testing.T) {
	command := exec.Command("go", "run", "../main", "--help")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI help command failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "pcage-audit audit") {
		t.Fatalf("CLI help output is missing the audit command: %s", output)
	}
}
