# File: scripts/registry-collection.ps1
# PowerShell script for collecting registry data for BloodHound analysis
# Based on the requirements document specifications

param(
    [string]$OutputFormat = "JSON"
)

# Initialize result object
$result = @{
    DeviceInfo = @{
        ComputerName = $env:COMPUTERNAME
        Domain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
        User = $env:USERNAME
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        ScriptVersion = "1.0"
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
}

# Function to safely get registry values
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
                # Get all values if no specific ones requested
                $key.GetValueNames() | ForEach-Object {
                    try {
                        $registryEntry.Values[$_] = $key.GetValue($_)
                    } catch {
                        $registryEntry.Values[$_] = "ACCESS_DENIED"
                    }
                }
            } else {
                # Get specific values
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
    }
    
    return $registryEntry
}

# 1. UAC and Privilege Settings
$uacData = Get-RegistryData -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Purpose "UAC and privilege settings analysis" -ValueNames @(
    "EnableLUA",
    "ConsentPromptBehaviorAdmin", 
    "ConsentPromptBehaviorUser",
    "PromptOnSecureDesktop"
)
$result.RegistryData += $uacData

# Check for UAC disabled
if ($uacData.Values.EnableLUA -eq 0) {
    $result.SecurityIndicators.UACDisabled = $true
    $result.Summary.HighRiskIndicators += "UAC_DISABLED"
}

# 2. Logon Settings and Potential Backdoors
$logonData = Get-RegistryData -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Purpose "Logon settings and potential backdoor detection" -ValueNames @(
    "Userinit",
    "Shell",
    "AutoAdminLogon",
    "DefaultUserName",
    "DefaultPassword"
)
$result.RegistryData += $logonData

# Check for auto admin logon
if ($logonData.Values.AutoAdminLogon -eq "1") {
    $result.SecurityIndicators.AutoAdminLogon = $true
    $result.Summary.HighRiskIndicators += "AUTO_ADMIN_LOGON"
}

# 3. LSA Security Settings
$lsaData = Get-RegistryData -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Purpose "LSA settings for credential access analysis" -ValueNames @(
    "RunAsPPL",
    "DisableRestrictedAdmin",
    "DisableRestrictedAdminOutboundCreds"
)
$result.RegistryData += $lsaData

# 4. Persistence Mechanisms - Run Keys
$runData = Get-RegistryData -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Purpose "Identify persistence mechanisms and startup programs"
$result.RegistryData += $runData

$runOnceData = Get-RegistryData -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Purpose "Identify persistence mechanisms and startup programs"
$result.RegistryData += $runOnceData

# Check for suspicious startup items
$suspiciousPatterns = @("powershell", "cmd", "wscript", "cscript", ".ps1", ".bat", ".vbs")
foreach ($entry in $runData.Values.GetEnumerator()) {
    foreach ($pattern in $suspiciousPatterns) {
        if ($entry.Value -like "*$pattern*") {
            $result.SecurityIndicators.SuspiciousStartupItems += "$($entry.Key): $($entry.Value)"
            break
        }
    }
}

foreach ($entry in $runOnceData.Values.GetEnumerator()) {
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

# 5. Service Configuration
$services = @("WinRM", "RemoteRegistry", "Schedule")
foreach ($service in $services) {
    $serviceData = Get-RegistryData -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$service" -Purpose "Service configuration analysis for attack vectors"
    $result.RegistryData += $serviceData
}

# Add additional security checks for service permissions
try {
    $weakServices = @()
    foreach ($service in $services) {
        $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
        if (Test-Path "Registry::$servicePath") {
            $serviceKey = Get-Item "Registry::$servicePath"
            $imagePath = $serviceKey.GetValue("ImagePath")
            if ($imagePath -and $imagePath -like "*\temp\*") {
                $weakServices += $service
            }
        }
    }
    
    if ($weakServices.Count -gt 0) {
        $result.SecurityIndicators.WeakServicePermissions = $true
        $result.Summary.HighRiskIndicators += "WEAK_SERVICE_PERMISSIONS"
    }
} catch {
    # Continue even if service permission check fails
}

# Output results
if ($OutputFormat -eq "JSON") {
    $jsonOutput = $result | ConvertTo-Json -Depth 10
    Write-Output $jsonOutput
} else {
    Write-Output $result
}

# Set exit code based on risk indicators
if ($result.Summary.HighRiskIndicators.Count -gt 0) {
    exit 1
} else {
    exit 0
}