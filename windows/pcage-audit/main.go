package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

func main() {
	args, hold := removeArgument(os.Args[1:], "--elevated-hold")
	err := execute(args, os.Stdout, os.Stderr, runtime.GOOS)
	if hold && isInteractiveInput() {
		fmt.Fprint(os.Stdout, "\nPress Enter to close this elevated PrivaCage window...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func execute(args []string, stdout, stderr io.Writer, goos string) error {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		return runWindowsCommand(args, stdout, stderr)
	}
	if goos != "windows" {
		return errors.New("this read-only audit requires Windows 10/11 and Windows PowerShell; no system changes were made")
	}
	return runWindowsCommand(args, stdout, stderr)
}

func writeTextReport(w io.Writer, result auditReport) error {
	if _, err := fmt.Fprintln(w, "⠿  PrivaCage — Windows privacy baseline"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Generated: %s\nMode: read-only; no network requests\n\n", result.GeneratedAt.Format(time.RFC3339)); err != nil {
		return err
	}
	for _, finding := range result.Checks {
		if _, err := fmt.Fprintf(w, "[%s / %s] %s\nObserved: %s\n%s\n", finding.Status, finding.Severity, finding.Title, finding.Observed, finding.Meaning); err != nil {
			return err
		}
		if finding.Recommendation != "" {
			if _, err := fmt.Fprintf(w, "Next step: %s\n", finding.Recommendation); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "Evidence: %s\n\n", finding.SourceURL); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "Summary: %d checks; %d review; %d unknown; %d not configured\n",
		result.Summary.Total, result.Summary.Review, result.Summary.Unknown, result.Summary.NotConfigured); err != nil {
		return err
	}
	for _, limitation := range result.Limitations {
		if _, err := fmt.Fprintf(w, "- Limit: %s\n", limitation); err != nil {
			return err
		}
	}
	return nil
}
