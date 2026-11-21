package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

const maximumSnapshotBytes = 64 * 1024

type firewallProfile struct {
	Name                 string "json:\"name\""
	Enabled              *bool  "json:\"enabled\""
	DefaultInboundAction string "json:\"default_inbound_action\""
	DefaultOutboundAction string "json:\"default_outbound_action\""
}

type registryPolicy struct {
	Configured bool "json:\"configured\""
	Value      *int "json:\"value\""
	InvalidType bool "json:\"invalid_type\""
	ReadError  bool "json:\"read_error\""
}

type appPrivacyPolicies struct {
	Location   registryPolicy "json:\"location\""
	Camera     registryPolicy "json:\"camera\""
	Microphone registryPolicy "json:\"microphone\""
}

type dnsServerConfig struct {
	InterfaceAlias  string   `json:"interface_alias"`
	AddressFamily   string   `json:"address_family"`
	ServerAddresses []string `json:"server_addresses"`
}

type userProxySnapshot struct {
	ReadError               bool  `json:"read_error"`
	ProxyEnableConfigured   bool  `json:"proxy_enable_configured"`
	ProxyEnabled            *bool `json:"proxy_enabled"`
	ProxyServerConfigured   bool  `json:"proxy_server_configured"`
	AutoConfigURLConfigured bool  `json:"auto_config_url_configured"`
}

type powershellSnapshot struct {
	FirewallProfiles  []firewallProfile  `json:"firewall_profiles"`
	FirewallReadError bool               `json:"firewall_read_error"`
	DiagnosticData    registryPolicy     `json:"diagnostic_data"`
	AppPrivacy        appPrivacyPolicies `json:"app_privacy"`
	DNSServers        []dnsServerConfig  `json:"dns_servers"`
	DNSReadError      bool               `json:"dns_read_error"`
	UserProxy         userProxySnapshot  `json:"user_proxy"`
}

var powershellAuditScript = strings.Join([]string{
	"$ErrorActionPreference = 'Stop'",
	"$ProgressPreference = 'SilentlyContinue'",
	"function Read-DwordPolicy([string]$Path, [string]$Name) {",
	"  try {",
	"    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return [ordered]@{ configured = $false; value = $null; invalid_type = $false; read_error = $false } }",
	"    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop",
	"    $property = $item.PSObject.Properties[$Name]",
	"    if ($null -eq $property) { return [ordered]@{ configured = $false; value = $null; invalid_type = $false; read_error = $false } }",
	"    if ($property.Value -isnot [System.Int32]) { return [ordered]@{ configured = $true; value = $null; invalid_type = $true; read_error = $false } }",
	"    return [ordered]@{ configured = $true; value = [int]$property.Value; invalid_type = $false; read_error = $false }",
	"  } catch { return [ordered]@{ configured = $false; value = $null; invalid_type = $false; read_error = $true } }",
	"}",
	"$firewallProfiles = @()",
	"$firewallReadError = $false",
	"try {",
	"  $firewallProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled; default_inbound_action = [string]$_.DefaultInboundAction; default_outbound_action = [string]$_.DefaultOutboundAction } })",
	"} catch { $firewallReadError = $true; $firewallProfiles = @() }",
	"$dnsServers = @()",
	"$dnsReadError = $false",
	"try {",
	"  $dnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {",
	"    $addresses = @($_.ServerAddresses | Where-Object { $_ -and $_.Trim() -ne '' })",
	"    if ($addresses.Count -gt 0) { [ordered]@{ interface_alias = [string]$_.InterfaceAlias; address_family = [string]$_.AddressFamily; server_addresses = $addresses } }",
	"  })",
	"} catch { $dnsReadError = $true; $dnsServers = @() }",
	"$proxy = [ordered]@{ read_error = $false; proxy_enable_configured = $false; proxy_enabled = $null; proxy_server_configured = $false; auto_config_url_configured = $false }",
	"try {",
	"  $proxyPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'",
	"  if (Test-Path -LiteralPath $proxyPath -ErrorAction Stop) {",
	"    $proxyItem = Get-ItemProperty -LiteralPath $proxyPath -ErrorAction Stop",
	"    $proxyEnable = $proxyItem.PSObject.Properties['ProxyEnable']",
	"    if ($null -ne $proxyEnable) {",
	"      $proxy.proxy_enable_configured = $true",
	"      if ($proxyEnable.Value -is [System.Int32]) { $proxy.proxy_enabled = ([int]$proxyEnable.Value -ne 0) }",
	"    }",
	"    $proxyServer = $proxyItem.PSObject.Properties['ProxyServer']",
	"    $proxy.proxy_server_configured = ($null -ne $proxyServer -and -not [string]::IsNullOrWhiteSpace([string]$proxyServer.Value))",
	"    $pac = $proxyItem.PSObject.Properties['AutoConfigURL']",
	"    $proxy.auto_config_url_configured = ($null -ne $pac -and -not [string]::IsNullOrWhiteSpace([string]$pac.Value))",
	"  }",
	"} catch { $proxy.read_error = $true }",
	"$result = [ordered]@{",
	"  firewall_profiles = $firewallProfiles",
	"  firewall_read_error = $firewallReadError",
	"  diagnostic_data = (Read-DwordPolicy 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' 'AllowTelemetry')",
	"  app_privacy = [ordered]@{",
	"    location = (Read-DwordPolicy 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy' 'LetAppsAccessLocation')",
	"    camera = (Read-DwordPolicy 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy' 'LetAppsAccessCamera')",
	"    microphone = (Read-DwordPolicy 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy' 'LetAppsAccessMicrophone')",
	"  }",
	"  dns_servers = $dnsServers",
	"  dns_read_error = $dnsReadError",
	"  user_proxy = $proxy",
	"}",
	"$result | ConvertTo-Json -Depth 8 -Compress",
}, "\n")

func collectWindowsSnapshot(ctx context.Context) (powershellSnapshot, error) {
	executable, err := exec.LookPath("powershell.exe")
	if err != nil {
		return powershellSnapshot{}, errors.New("Windows PowerShell (powershell.exe) was not found")
	}
	command := exec.CommandContext(ctx, executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", powershellAuditScript)
	output, err := command.Output()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return powershellSnapshot{}, errors.New("Windows policy collection timed out after 20 seconds")
		}
		return powershellSnapshot{}, errors.New("could not query local Windows settings; verify PowerShell and the NetSecurity module are available")
	}
	return decodeSnapshot(output)
}

func decodeSnapshot(data []byte) (powershellSnapshot, error) {
	if len(data) == 0 {
		return powershellSnapshot{}, errors.New("Windows PowerShell returned no audit data")
	}
	if len(data) > maximumSnapshotBytes {
		return powershellSnapshot{}, fmt.Errorf("Windows audit snapshot exceeded the %d-byte safety limit", maximumSnapshotBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot powershellSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return powershellSnapshot{}, fmt.Errorf("Windows PowerShell returned an invalid snapshot: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return powershellSnapshot{}, errors.New("Windows PowerShell returned multiple JSON values")
		}
		return powershellSnapshot{}, fmt.Errorf("Windows PowerShell returned trailing data: %w", err)
	}
	return snapshot, nil
}
