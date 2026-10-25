package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const win11DebloatEntryPoint = "Win11Debloat.ps1"

// launchWin11Debloat starts the pinned Win11Debloat component. No settings are applied by this wrapper;
// the upstream UI/CLI owns its own selections, elevation, and apply flow.
func launchWin11Debloat(args []string, stdout, stderr io.Writer) error {
	scriptPath, err := resolveWin11DebloatScript()
	if err != nil {
		return err
	}
	powershellPath, err := resolveWindowsPowerShellFrom(
		os.Getenv("SystemRoot"),
		os.Getenv("PROCESSOR_ARCHITEW6432") != "",
		isRegularFile,
	)
	if err != nil {
		return err
	}

	commandArgs := []string{"-NoLogo", "-NoProfile", "-File", scriptPath}
	commandArgs = append(commandArgs, args...)
	command := exec.Command(powershellPath, commandArgs...)
	command.Stdin = os.Stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return fmt.Errorf("Win11Debloat exited with code %d", exitError.ExitCode())
		}
		return fmt.Errorf("launch Win11Debloat: %w", err)
	}
	return nil
}

func resolveWin11DebloatScript() (string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve current directory: %w", err)
	}
	executablePath, _ := os.Executable()
	return findWin11DebloatScriptFrom(workingDirectory, executablePath)
}

func findWin11DebloatScriptFrom(workingDirectory, executablePath string) (string, error) {
	roots := []string{workingDirectory}
	if executablePath != "" {
		roots = append(roots, filepath.Dir(executablePath))
	}

	seen := make(map[string]struct{})
	for _, root := range roots {
		candidates := []string{
			filepath.Join(root, "windows", "Win11Debloat", win11DebloatEntryPoint),
			filepath.Join(root, "Win11Debloat", win11DebloatEntryPoint),
			filepath.Join(root, "..", "Win11Debloat", win11DebloatEntryPoint),
		}
		for _, candidate := range candidates {
			absolute, err := filepath.Abs(candidate)
			if err != nil {
				continue
			}
			absolute = filepath.Clean(absolute)
			if _, duplicate := seen[absolute]; duplicate {
				continue
			}
			seen[absolute] = struct{}{}
			if isRegularFile(absolute) {
				return absolute, nil
			}
		}
	}
	return "", errors.New("Win11Debloat is not initialized; from the PrivaCage repository root run: git submodule update --init --recursive")
}

func resolveWindowsPowerShellFrom(systemRoot string, wow64 bool, fileExists func(string) bool) (string, error) {
	if systemRoot == "" {
		return "", errors.New("SystemRoot is missing; cannot resolve trusted Windows PowerShell 5.1")
	}
	candidates := make([]string, 0, 2)
	if wow64 {
		candidates = append(candidates, filepath.Join(systemRoot, "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"))
	}
	candidates = append(candidates, filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"))
	for _, candidate := range candidates {
		if fileExists(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("Windows PowerShell 5.1 was not found under SystemRoot; Win11Debloat requires powershell.exe, not pwsh.exe")
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
