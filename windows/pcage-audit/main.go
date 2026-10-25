package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

func main() {
	if err := execute(os.Args[1:], os.Stdout, os.Stderr, runtime.GOOS); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func execute(args []string, stdout, stderr io.Writer, goos string) error {
	flags := flag.NewFlagSet("pcage-audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *format != "text" && *format != "json" {
		return errors.New("format must be text or json")
	}
	if goos != "windows" {
		return errors.New("this read-only audit requires Windows 10/11 and Windows PowerShell; no system changes were made")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	snapshot, err := collectWindowsSnapshot(ctx)
	if err != nil {
		return err
	}
	result := buildReport(snapshot, time.Now().UTC())
	if *format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	return writeTextReport(stdout, result)
}

func writeTextReport(w io.Writer, result auditReport) error {
	if _, err := fmt.Fprintln(w, "PrivaCage — Windows privacy baseline"); err != nil {
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
