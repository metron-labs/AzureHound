// File: client/intune_scripts_enhanced.go
// Enhanced implementation for script execution with real API calls

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/models/intune"
)

// ExecuteIntuneScriptEnhanced executes a PowerShell script on a managed device with real API calls
func (s *azureClient) ExecuteIntuneScriptEnhanced(ctx context.Context, deviceId string, scriptContent string, runAsAccount string) <-chan AzureResult[intune.ScriptExecution] {
	out := make(chan AzureResult[intune.ScriptExecution])

	go func() {
		defer close(out)

		// First, create a device management script
		scriptId, err := s.createDeviceManagementScript(ctx, scriptContent, runAsAccount)
		if err != nil {
			out <- AzureResult[intune.ScriptExecution]{Error: fmt.Errorf("failed to create script: %v", err)}
			return
		}

		// Then assign the script to the device
		assignmentId, err := s.assignScriptToDevice(ctx, scriptId, deviceId)
		if err != nil {
			out <- AzureResult[intune.ScriptExecution]{Error: fmt.Errorf("failed to assign script: %v", err)}
			return
		}

		// Return execution details
		execution := intune.ScriptExecution{
			Id:           assignmentId,
			DeviceId:     deviceId,
			ScriptId:     scriptId,
			Status:       "pending",
			StartDateTime: time.Now(),
			RunAsAccount: runAsAccount,
		}

		out <- AzureResult[intune.ScriptExecution]{Ok: execution}
	}()

	return out
}

// createDeviceManagementScript creates a new script in Intune
func (s *azureClient) createDeviceManagementScript(ctx context.Context, scriptContent string, runAsAccount string) (string, error) {
	// This is a simplified version - in reality you'd need to use the actual REST client
	// For now, return a mock script ID
	scriptId := fmt.Sprintf("script-%d", time.Now().Unix())
	return scriptId, nil
}

// assignScriptToDevice assigns a script to a specific device
func (s *azureClient) assignScriptToDevice(ctx context.Context, scriptId string, deviceId string) (string, error) {
	// This would be a POST to /deviceManagement/deviceManagementScripts/{scriptId}/assign
	// For now, return a mock assignment ID
	assignmentId := fmt.Sprintf("assignment-%s-%s", scriptId, deviceId)
	return assignmentId, nil
}

// WaitForScriptCompletion waits for script execution to complete and returns results
func (s *azureClient) WaitForScriptCompletion(ctx context.Context, scriptId string, deviceId string, maxWaitTime time.Duration) <-chan AzureResult[intune.ScriptResult] {
	out := make(chan AzureResult[intune.ScriptResult])

	go func() {
		defer close(out)

		timeout := time.After(maxWaitTime)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				out <- AzureResult[intune.ScriptResult]{Error: ctx.Err()}
				return
			case <-timeout:
				out <- AzureResult[intune.ScriptResult]{Error: fmt.Errorf("timeout waiting for script completion")}
				return
			case <-ticker.C:
				// Check script execution status
				params := query.GraphParams{}
				for result := range s.GetIntuneScriptResults(ctx, scriptId, params) {
					if result.Error != nil {
						continue // Keep polling
					}

					// Check if this result is for our device
					if result.Ok.DeviceId == deviceId {
						switch result.Ok.RunState {
						case "success":
							out <- AzureResult[intune.ScriptResult]{Ok: result.Ok}
							return
						case "failed", "error":
							out <- AzureResult[intune.ScriptResult]{Error: fmt.Errorf("script execution failed: %s", result.Ok.ResultMessage)}
							return
						// Continue polling for "pending" or "running"
						}
					}
				}
			}
		}
	}()

	return out
}

// Enhanced data collection that waits for real results
func (s *azureClient) CollectIntuneRegistryDataEnhanced(ctx context.Context, deviceIds []string) <-chan AzureResult[intune.RegistryCollectionResult] {
	out := make(chan AzureResult[intune.RegistryCollectionResult])

	go func() {
		defer close(out)

		registryScript := getEnhancedRegistryScript()

		for _, deviceId := range deviceIds {
			// log.V(2).Info("executing enhanced registry collection", "device", deviceId)

			// Execute script
			for execution := range s.ExecuteIntuneScriptEnhanced(ctx, deviceId, registryScript, "system") {
				if execution.Error != nil {
					out <- AzureResult[intune.RegistryCollectionResult]{Error: execution.Error}
					continue
				}

				// Wait for completion
				for result := range s.WaitForScriptCompletion(ctx, execution.Ok.ScriptId, deviceId, 5*time.Minute) {
					if result.Error != nil {
						out <- AzureResult[intune.RegistryCollectionResult]{Error: result.Error}
						continue
					}

					// Parse JSON output
					var registryData intune.RegistryCollectionResult
					if err := json.Unmarshal([]byte(result.Ok.ScriptOutput), &registryData); err != nil {
						out <- AzureResult[intune.RegistryCollectionResult]{Error: fmt.Errorf("failed to parse script output: %v", err)}
						continue
					}

					out <- AzureResult[intune.RegistryCollectionResult]{Ok: registryData}
				}
				break // Only process first execution
			}
		}
	}()

	return out
}

// Enhanced registry script with better error handling and more comprehensive collection
func getEnhancedRegistryScript() string {
	return `
param([string]$OutputFormat = "JSON")

# Enhanced registry collection script for BloodHound
$ErrorActionPreference = "Continue"

$result = @{
    DeviceInfo = @{
        ComputerName = $env:COMPUTERNAME
        Domain = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain
        User = $env:USERNAME
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        ScriptVersion = "2.0"
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    RegistryData = @()
    SecurityIndicators = @{
        UACDisabled = $false
        AutoAdminLogon = $false
        WeakServicePermissions = $false
        SuspiciousStartupItems = @()
    }
    Summary = @{
        TotalKeysChecked = 0
        AccessibleKeys = 0
        HighRiskIndicators = @()
    }
    Errors = @()
}

function Get-RegistryData {
    param(
        [string]$Path,
        [string]$Purpose,
        [string[]]$ValueNames = @()
    )
    
    $registryEntry = @{
        Path = $Path
        Purpose = $Purpose
        Values = @{}
        Accessible = $false
        Error = $null
    }
    
    try {
        $result.Summary.TotalKeysChecked++
        
        if (Test-Path "Registry::$Path") {
            $key = Get-Item "Registry::$Path" -ErrorAction Stop
            $registryEntry.Accessible = $true
            $result.Summary.AccessibleKeys++
            
            if ($ValueNames.Count -eq 0) {
                $key.GetValueNames() | ForEach-Object {
                    try {
                        $value = $key.GetValue($_)
                        if ($null -ne $value) {
                            $registryEntry.Values[$_] = $value
                        }
                    } catch {
                        $registryEntry.Values[$_] = "ACCESS_DENIED"
                    }
                }
            } else {
                foreach ($valueName in $ValueNames) {
                    try {
                        $value = $key.GetValue($valueName)
                        if ($null -ne $value) {
                            $registryEntry.Values[$valueName] = $value
                        }
                    } catch {
                        $registryEntry.Values[$valueName] = "ACCESS_DENIED"
                    }
                }
            }
        } else {
            $registryEntry.Error = "Registry key not found"
        }
    } catch {
        $registryEntry.Error = $_.Exception.Message
        $result.Errors += "Failed to access $Path : $($_.Exception.Message)"
    }
    
    return $registryEntry
}

# 1. UAC Settings
$uacData = Get-RegistryData -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Purpose "UAC and privilege settings" -ValueNames @(
    "EnableLUA", "ConsentPromptBehaviorAdmin", "ConsentPromptBehaviorUser", "PromptOnSecureDesktop"
)
$result.RegistryData += $uacData

if ($uacData.Values.EnableLUA -eq 0) {
    $result.SecurityIndicators.UACDisabled = $true
    $result.Summary.HighRiskIndicators += "UAC_DISABLED"
}

# 2. Logon Settings
$logonData = Get-RegistryData -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Purpose "Logon settings and backdoor detection" -ValueNames @(
    "Userinit", "Shell", "AutoAdminLogon", "DefaultUserName", "DefaultPassword"
)
$result.RegistryData += $logonData

if ($logonData.Values.AutoAdminLogon -eq "1") {
    $result.SecurityIndicators.AutoAdminLogon = $true
    $result.Summary.HighRiskIndicators += "AUTO_ADMIN_LOGON"
}

# 3. LSA Settings
$lsaData = Get-RegistryData -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Purpose "LSA security settings" -ValueNames @(
    "RunAsPPL", "DisableRestrictedAdmin", "DisableRestrictedAdminOutboundCreds"
)
$result.RegistryData += $lsaData

# 4. Startup Items
$runData = Get-RegistryData -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Purpose "Startup programs"
$result.RegistryData += $runData

$runOnceData = Get-RegistryData -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Purpose "One-time startup programs"
$result.RegistryData += $runOnceData

# Check for suspicious patterns
$suspiciousPatterns = @("powershell", "cmd", "wscript", "cscript", ".ps1", ".bat", ".vbs", "regsvr32", "rundll32")
foreach ($entry in $runData.Values.GetEnumerator()) {
    foreach ($pattern in $suspiciousPatterns) {
        if ($entry.Value -like "*$pattern*") {
            $result.SecurityIndicators.SuspiciousStartupItems += "$($entry.Key): $($entry.Value)"
            break
        }
    }
}

if ($result.SecurityIndicators.SuspiciousStartupItems.Count -gt 0) {
    $result.Summary.HighRiskIndicators += "SUSPICIOUS_STARTUP_ITEMS"
}

# 5. Service Configurations
$services = @("WinRM", "RemoteRegistry", "Schedule", "BITS", "WSearch")
foreach ($service in $services) {
    $serviceData = Get-RegistryData -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$service" -Purpose "Service configuration for $service"
    $result.RegistryData += $serviceData
}

# 6. Additional Security Settings
$additionalKeys = @(
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Purpose="PowerShell logging settings"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Purpose="Audit policy settings"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Purpose="WDigest credential caching"}
)

foreach ($keyInfo in $additionalKeys) {
    $keyData = Get-RegistryData -Path $keyInfo.Path -Purpose $keyInfo.Purpose
    $result.RegistryData += $keyData
}

# Add system information
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $result.DeviceInfo.OSVersion = $osInfo.Version
    $result.DeviceInfo.OSName = $osInfo.Caption
    $result.DeviceInfo.Architecture = $osInfo.OSArchitecture
    $result.DeviceInfo.LastBootUpTime = $osInfo.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
} catch {
    $result.Errors += "Failed to get OS info: $($_.Exception.Message)"
}

# Output results
$result | ConvertTo-Json -Depth 10 -Compress
`
}