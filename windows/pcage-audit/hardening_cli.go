package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func runWindowsCommand(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		if !isInteractiveInput() {
			printWindowsUsage(stdout)
			return nil
		}
		return runInteractiveConsole(os.Stdin, stdout, stderr)
	}
	command := args[0]
	commandArgs := args[1:]
	if strings.HasPrefix(command, "-") {
		command = "audit"
		commandArgs = args
	}
	switch command {
	case "help", "-h", "--help":
		printWindowsUsage(stdout)
		return nil
	case "audit":
		return executeAudit(commandArgs, stdout, stderr)
	case "plan":
		return executePlan(commandArgs, stdout, stderr)
	case "apply", "restore", "verify":
		return executeHardening(command, commandArgs, stdout, stderr)
	case "ui":
		return runInteractiveConsole(os.Stdin, stdout, stderr)
	case "debloat":
		return launchWin11Debloat(commandArgs, stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q; run pcage-audit help", command)
	}
}

func executePlan(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profile := flags.String("profile", "balanced", "hardening profile: balanced or strict")
	format := flags.String("format", "text", "output format: text or json")
	blockOutbound := flags.Bool("block-outbound-by-default", false, "set all firewall profiles' default outbound action to Block")
	isolateOutbound := flags.Bool("isolate-network", false, "add an explicit outbound block rule for all programs")
	confirmNetwork := flags.Bool("confirm-network-disruption", false, "acknowledge the network disruption described by this plan")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *format != "text" && *format != "json" {
		return errors.New("format must be text or json")
	}
	if (*blockOutbound || *isolateOutbound) && !*confirmNetwork {
		return errors.New("network-control preview requires --confirm-network-disruption so its effect is explicit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	metadata, err := collectWindowsMetadata(ctx)
	if err != nil {
		return err
	}
	plan, err := buildHardeningPlan(*profile, metadata, *blockOutbound, *isolateOutbound)
	if err != nil {
		return err
	}
	return printHardeningPlan(stdout, plan, *format)
}

func executeHardening(command string, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	profile := flags.String("profile", "balanced", "hardening profile: balanced or strict")
	format := flags.String("format", "text", "output format: text or json")
	confirm := flags.Bool("confirm", false, "confirm this specific hardening profile should be applied")
	confirmRestore := flags.Bool("confirm-restore", false, "confirm restoring the previously captured settings")
	blockOutbound := flags.Bool("block-outbound-by-default", false, "set default outbound action to Block")
	isolateOutbound := flags.Bool("isolate-network", false, "add an all-program outbound firewall block rule")
	confirmNetwork := flags.Bool("confirm-network-disruption", false, "confirm that network-dependent services may stop working")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *format != "text" && *format != "json" {
		return errors.New("format must be text or json")
	}
	if command == "apply" {
		if !*confirm {
			return errors.New("applying a policy requires --confirm; preview all planned changes with 'plan' first")
		}
		if *blockOutbound && *isolateOutbound {
			return errors.New("choose either --block-outbound-by-default or --isolate-network, not both")
		}
		if (*blockOutbound || *isolateOutbound) && !*confirmNetwork {
			return errors.New("network controls require --confirm-network-disruption; preview them with 'plan' first")
		}
	} else if *blockOutbound || *isolateOutbound || *confirmNetwork {
		return errors.New("network-control flags are valid only with 'plan' or 'apply'")
	}
	if command == "restore" && !*confirmRestore {
		return errors.New("restore requires --confirm-restore because it changes Windows policy and firewall settings")
	}
	if command != "apply" && (*profile != "balanced") {
		return errors.New("--profile is only valid with apply; verify and restore use the active backup")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if command == "apply" || command == "restore" || command == "verify" {
		admin, err := isWindowsAdministrator(ctx)
		if err != nil {
			return err
		}
		if !admin {
			childArgs := append([]string{command}, args...)
			return relaunchElevated(ctx, childArgs)
		}
	}

	var data []byte
	var err error
	switch command {
	case "apply":
		metadata, metadataErr := collectWindowsMetadata(ctx)
		if metadataErr != nil {
			return metadataErr
		}
		plan, planErr := buildHardeningPlan(*profile, metadata, *blockOutbound, *isolateOutbound)
		if planErr != nil {
			return planErr
		}
		data, err = applyWindowsHardening(ctx, plan)
	case "verify":
		data, err = verifyWindowsHardening(ctx)
	case "restore":
		data, err = restoreWindowsHardening(ctx)
	default:
		return fmt.Errorf("unsupported hardening action %q", command)
	}
	if err != nil {
		return err
	}
	if err := validateHardeningResult(data); err != nil {
		return fmt.Errorf("Windows returned an invalid hardening result: %w", err)
	}
	if err := formatActionResult(stdout, data, *format); err != nil {
		return err
	}
	if command == "verify" {
		var verification hardeningVerification
		if err := decodeStrictJSON(data, &verification); err == nil && !verification.Success {
			return errors.New("one or more managed policy checks show drift or an unknown state; see the verification report")
		}
	}
	var result hardeningResult
	if err := decodeStrictJSON(data, &result); err == nil && !result.Success {
		return errors.New("Windows did not confirm that the hardening action completed successfully; keep the backup and review the result")
	}
	return nil
}

func executeAudit(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *format != "text" && *format != "json" {
		return errors.New("format must be text or json")
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

func formatActionResult(w io.Writer, data []byte, format string) error {
	var result hardeningResult
	if err := decodeStrictJSON(data, &result); err == nil && result.SchemaVersion == 1 {
		if format == "json" {
			encoder := json.NewEncoder(w)
			encoder.SetIndent("", "  ")
			return encoder.Encode(result)
		}
		return writeHardeningResultText(w, result)
	}
	var verification hardeningVerification
	if err := decodeStrictJSON(data, &verification); err != nil || verification.SchemaVersion != 1 {
		return errors.New("could not parse the Windows action result")
	}
	if format == "json" {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(verification)
	}
	return writeVerificationText(w, verification)
}

func validateHardeningResult(data []byte) error {
	var result hardeningResult
	if err := decodeStrictJSON(data, &result); err == nil {
		if result.SchemaVersion != 1 || result.Action == "" {
			return errors.New("unsupported action result schema")
		}
		return nil
	}
	var verification hardeningVerification
	if err := decodeStrictJSON(data, &verification); err != nil || verification.SchemaVersion != 1 || verification.Action != "verify" {
		return errors.New("unsupported verification result schema")
	}
	return nil
}

func writeHardeningResultText(w io.Writer, result hardeningResult) error {
	c := terminalColors()
	if _, err := fmt.Fprintf(w, "%s⠿  PRIVACAGE / WINDOWS PRIVACY CONTROL%s\n", c.white, c.reset); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s────────────────────────────────────────────────────────────%s\n", c.muted, c.reset); err != nil {
		return err
	}
	status := "NOT VERIFIED"
	if result.Success && result.Verified {
		status = "VERIFIED"
	}
	if _, err := fmt.Fprintf(w, "ACTION   %s\nPROFILE  %s\nRESULT   %s%s%s\n", strings.ToUpper(result.Action), result.Profile, c.white, status, c.reset); err != nil {
		return err
	}
	if result.AppliedPolicies > 0 || result.VerifiedPolicies > 0 {
		if _, err := fmt.Fprintf(w, "POLICIES %d applied · %d verified\n", result.AppliedPolicies, result.VerifiedPolicies); err != nil {
			return err
		}
	}
	if result.NetworkAction != "" {
		if _, err := fmt.Fprintf(w, "NETWORK  %s\n", result.NetworkAction); err != nil {
			return err
		}
	}
	if result.BackupPath != "" {
		if _, err := fmt.Fprintf(w, "BACKUP   %s\n", result.BackupPath); err != nil {
			return err
		}
	}
	for _, skipped := range result.Skipped {
		if _, err := fmt.Fprintf(w, "SKIPPED  %s\n", skipped); err != nil {
			return err
		}
	}
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(w, "%sNOTE     %s%s\n", c.muted, warning, c.reset); err != nil {
			return err
		}
	}
	for _, failure := range result.Errors {
		if _, err := fmt.Fprintf(w, "%sERROR    %s%s\n", c.white, failure, c.reset); err != nil {
			return err
		}
	}
	return nil
}

func writeVerificationText(w io.Writer, result hardeningVerification) error {
	c := terminalColors()
	if _, err := fmt.Fprintf(w, "%s⠿  PRIVACAGE / WINDOWS POLICY VERIFICATION%s\n", c.white, c.reset); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s────────────────────────────────────────────────────────────%s\n", c.muted, c.reset); err != nil {
		return err
	}
	for _, check := range result.Checks {
		if _, err := fmt.Fprintf(w, "[%s] %s\n  expected: %s\n  observed: %s\n", strings.ToUpper(check.Status), check.ID, check.Expected, check.Observed); err != nil {
			return err
		}
	}
	status := "DRIFT OR UNKNOWN STATE"
	if result.Success {
		status = "ALL CHECKS MATCH"
	}
	if _, err := fmt.Fprintf(w, "RESULT   %s%s%s\n", c.white, status, c.reset); err != nil {
		return err
	}
	for _, warning := range result.Warnings {
		if _, err := fmt.Fprintf(w, "%sNOTE     %s%s\n", c.muted, warning, c.reset); err != nil {
			return err
		}
	}
	return nil
}

func printHardeningPlan(w io.Writer, plan hardeningPlan, format string) error {
	if format == "json" {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	}
	c := terminalColors()
	if _, err := fmt.Fprintf(w, "%s⠿  PRIVACAGE / WINDOWS HARDENING PLAN%s\n", c.white, c.reset); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s────────────────────────────────────────────────────────────%s\n", c.muted, c.reset); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "PROFILE  %s\nEDITION  %s\nBUILD    %d\nPOLICIES %d\n", strings.ToUpper(plan.Profile), plan.EditionID, plan.BuildNumber, len(plan.Changes)); err != nil {
		return err
	}
	for _, change := range plan.Changes {
		if _, err := fmt.Fprintf(w, "  • %s = %d\n    %s\n    Evidence: %s\n", change.Name, change.Value, change.Description, change.SourceURL); err != nil {
			return err
		}
	}
	for _, skipped := range plan.Skipped {
		if _, err := fmt.Fprintf(w, "SKIPPED  %s\n", skipped); err != nil {
			return err
		}
	}
	for _, warning := range plan.Warnings {
		if _, err := fmt.Fprintf(w, "%sNOTE     %s%s\n", c.muted, warning, c.reset); err != nil {
			return err
		}
	}
	if plan.BlockOutboundByDefault {
		if _, err := fmt.Fprintln(w, "NETWORK  Set outbound defaults to Block (explicit allow rules remain)."); err != nil {
			return err
		}
	}
	if plan.IsolateOutbound {
		if _, err := fmt.Fprintln(w, "NETWORK  Add an explicit all-program outbound firewall block rule."); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "BACKUP   %s\n", activeBackupPathDisplay()); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "No changes have been made. Apply only after reviewing every listed effect."); err != nil {
		return err
	}
	return nil
}

func printWindowsUsage(w io.Writer) {
	fmt.Fprintln(w, "PrivaCage — Windows Privacy Control")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  pcage-audit                  Open the monochrome interactive console")
	fmt.Fprintln(w, "  pcage-audit audit            Read current firewall and privacy-policy state")
	fmt.Fprintln(w, "  pcage-audit plan --profile balanced|strict")
	fmt.Fprintln(w, "  pcage-audit apply --profile balanced --confirm")
	fmt.Fprintln(w, "  pcage-audit verify           Verify the active PrivaCage profile")
	fmt.Fprintln(w, "  pcage-audit restore --confirm-restore")
	fmt.Fprintln(w, "  pcage-audit debloat [Win11Debloat parameters]  Open the Windows customization GUI")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Optional high-impact network controls; preview first and confirm explicitly:")
	fmt.Fprintln(w, "  pcage-audit plan --profile balanced --block-outbound-by-default --confirm-network-disruption")
	fmt.Fprintln(w, "  pcage-audit apply --profile balanced --isolate-network --confirm --confirm-network-disruption")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Balanced minimizes documented diagnostics and Activity Feed sharing.")
	fmt.Fprintln(w, "Strict additionally denies selected Windows-app capabilities and disables Windows Error Reporting.")
	fmt.Fprintln(w, "Mutating audit-profile actions request UAC elevation and save a protected local rollback file.")
	fmt.Fprintln(w, "The debloat command launches the separately pinned Win11Debloat tool; review its selections before applying changes.")
	fmt.Fprintln(w, "This cannot guarantee zero Windows traffic or control firmware and out-of-band channels.")
}

type palette struct {
	white string
	muted string
	reset string
}

func terminalColors() palette {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return palette{}
	}
	return palette{white: "\x1b[97m", muted: "\x1b[90m", reset: "\x1b[0m"}
}

func runInteractiveConsole(input io.Reader, output, stderr io.Writer) error {
	reader := bufio.NewReader(input)
	for {
		c := terminalColors()
		fmt.Fprintf(output, "\n%s⠿  PRIVACAGE%s  /  %sWINDOWS PRIVACY CONTROL%s\n", c.white, c.reset, c.muted, c.reset)
		fmt.Fprintf(output, "%s────────────────────────────────────────────────────────────%s\n", c.muted, c.reset)
		fmt.Fprintln(output, "  1  Read current privacy baseline")
		fmt.Fprintln(output, "  2  Preview balanced profile")
		fmt.Fprintln(output, "  3  Apply balanced profile")
		fmt.Fprintln(output, "  4  Preview strict profile")
		fmt.Fprintln(output, "  5  Apply strict profile")
		fmt.Fprintln(output, "  6  Verify active profile")
		fmt.Fprintln(output, "  7  Restore captured settings")
		fmt.Fprintln(output, "  8  Preview emergency network isolation")
		fmt.Fprintln(output, "  9  Apply emergency network isolation")
		fmt.Fprintln(output, " 10  Open Win11Debloat customization GUI")
		fmt.Fprintln(output, "  0  Exit")
		fmt.Fprint(output, "\nSelect: ")
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return nil
		}
		choice := strings.TrimSpace(line)
		if choice == "0" {
			return nil
		}
		switch choice {
		case "1":
			if err := executeAudit(nil, output, stderr); err != nil {
				fmt.Fprintf(stderr, "ERROR: %v\n", err)
			}
		case "2":
			if err := executePlan([]string{"--profile", "balanced"}, output, stderr); err != nil {
				fmt.Fprintf(stderr, "ERROR: %v\n", err)
			}
		case "3":
			if err := interactiveConfirm(reader, output, "APPLY BALANCED"); err == nil {
				if err := executeHardening("apply", []string{"--profile", "balanced", "--confirm"}, output, stderr); err != nil {
					fmt.Fprintf(stderr, "ERROR: %v\n", err)
				}
			}
		case "4":
			if err := executePlan([]string{"--profile", "strict"}, output, stderr); err != nil {
				fmt.Fprintf(stderr, "ERROR: %v\n", err)
			}
		case "5":
			if err := interactiveConfirm(reader, output, "APPLY STRICT"); err == nil {
				if err := executeHardening("apply", []string{"--profile", "strict", "--confirm"}, output, stderr); err != nil {
					fmt.Fprintf(stderr, "ERROR: %v\n", err)
				}
			}
		case "6":
			if err := executeHardening("verify", nil, output, stderr); err != nil {
				fmt.Fprintf(stderr, "ERROR: %v\n", err)
			}
		case "7":
			if err := interactiveConfirm(reader, output, "RESTORE"); err == nil {
				if err := executeHardening("restore", []string{"--confirm-restore"}, output, stderr); err != nil {
					fmt.Fprintf(stderr, "ERROR: %v\n", err)
				}
			}
		case "8":
			if err := executePlan([]string{"--profile", "balanced", "--isolate-network", "--confirm-network-disruption"}, output, stderr); err != nil {
				fmt.Fprintf(stderr, "ERROR: %v\n", err)
			}
		case "9":
			fmt.Fprintln(output, "This action will block outbound traffic for all programs, including network-dependent Windows services.")
			if err := interactiveConfirm(reader, output, "ISOLATE NETWORK"); err == nil {
				args := []string{"--profile", "balanced", "--confirm", "--isolate-network", "--confirm-network-disruption"}
				if err := executeHardening("apply", args, output, stderr); err != nil {
					fmt.Fprintf(stderr, "ERROR: %v\n", err)
				}
			}
		case "10":
			if err := launchWin11Debloat(nil, output, stderr); err != nil {
				fmt.Fprintf(stderr, "ERROR: %v\n", err)
			}
		default:
			fmt.Fprintln(output, "Choose one of the displayed numbers.")
		}
	}
}

func interactiveConfirm(reader *bufio.Reader, output io.Writer, expected string) error {
	fmt.Fprintf(output, "Type %q to continue (anything else cancels): ", expected)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	if strings.TrimSpace(line) != expected {
		fmt.Fprintln(output, "Cancelled. No change was requested.")
		return errors.New("confirmation did not match")
	}
	return nil
}

func validUserSID(sid string) bool {
	if !strings.HasPrefix(sid, "S-1-5-21-") {
		return false
	}
	parts := strings.Split(sid, "-")
	if len(parts) != 8 {
		return false
	}
	for _, part := range parts[2:] {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func quoteWindowsArgument(argument string) string {
	if argument != "" && !strings.ContainsAny(argument, " \t\"") {
		return argument
	}
	var builder strings.Builder
	builder.WriteByte('"')
	backslashes := 0
	for _, char := range argument {
		if char == '\\' {
			backslashes++
			continue
		}
		if char == '"' {
			builder.WriteString(strings.Repeat("\\", backslashes*2+1))
			builder.WriteRune(char)
			backslashes = 0
			continue
		}
		builder.WriteString(strings.Repeat("\\", backslashes))
		backslashes = 0
		builder.WriteRune(char)
	}
	builder.WriteString(strings.Repeat("\\", backslashes*2))
	builder.WriteByte('"')
	return builder.String()
}

func relaunchElevated(ctx context.Context, args []string) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate PrivaCage for UAC elevation: %w", err)
	}
	childArgs := append([]string(nil), args...)
	childArgs = append(childArgs, "--elevated-hold")
	quoted := make([]string, 0, len(childArgs))
	for _, argument := range childArgs {
		quoted = append(quoted, quoteWindowsArgument(argument))
	}
	argumentLine := strings.Join(quoted, " ")
	script := strings.Join([]string{
		"$ErrorActionPreference='Stop'",
		"$exe='" + strings.ReplaceAll(executable, "'", "''") + "'",
		"$arguments='" + strings.ReplaceAll(argumentLine, "'", "''") + "'",
		"$process=Start-Process -FilePath $exe -ArgumentList $arguments -Verb RunAs -Wait -PassThru -ErrorAction Stop",
		"if ($process.ExitCode -ne 0) { throw ('Elevated PrivaCage action exited with code '+$process.ExitCode) }",
		"Write-Output 'Elevated PrivaCage action completed.'",
	}, "\n")
	if _, err := runPowerShellScript(ctx, script); err != nil {
		return fmt.Errorf("UAC elevation was cancelled or the elevated action failed: %w", err)
	}
	return nil
}

func removeArgument(args []string, target string) ([]string, bool) {
	filtered := make([]string, 0, len(args))
	found := false
	for _, arg := range args {
		if arg == target {
			found = true
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered, found
}
