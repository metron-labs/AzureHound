# File: scripts/local-groups.ps1
# PowerShell script for collecting local group membership data for BloodHound analysis

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
    LocalGroups = @{}
    Summary = @{
        TotalGroups = 0
        TotalMembers = 0
        AdminGroupMembers = 0
    }
}

# Target groups that are relevant for BloodHound analysis
$targetGroups = @(
    "Administrators",
    "Remote Desktop Users",
    "Power Users",
    "Backup Operators",
    "Server Operators",
    "Account Operators",
    "Print Operators",
    "Replicator",
    "Network Configuration Operators",
    "Performance Monitor Users",
    "Performance Log Users",
    "Distributed COM Users",
    "IIS_IUSRS",
    "Cryptographic Operators",
    "Event Log Readers",
    "Certificate Service DCOM Access",
    "RDS Remote Access Servers",
    "RDS Endpoint Servers",
    "RDS Management Servers",
    "Hyper-V Administrators",
    "Access Control Assistance Operators",
    "Remote Management Users"
)

# Function to get group members safely
function Get-LocalGroupMembers {
    param(
        [string]$GroupName
    )
    
    $members = @()
    
    try {
        # Try using Get-LocalGroupMember (Windows 10/Server 2016+)
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            $groupMembers = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
            foreach ($member in $groupMembers) {
                $memberInfo = @{
                    Name = $member.Name
                    SID = $member.SID.Value
                    ObjectClass = $member.ObjectClass
                    PrincipalSource = $member.PrincipalSource
                }
                $members += $memberInfo
            }
        } else {
            # Fallback to net localgroup command for older systems
            $output = net localgroup "$GroupName" 2>$null
            if ($LASTEXITCODE -eq 0) {
                $inMemberSection = $false
                foreach ($line in $output) {
                    if ($line -match "^-+$") {
                        $inMemberSection = $true
                        continue
                    }
                    if ($inMemberSection -and $line.Trim() -ne "" -and $line -notmatch "The command completed successfully") {
                        $memberName = $line.Trim()
                        if ($memberName -ne "") {
                            # Try to resolve SID
                            try {
                                $sid = (New-Object System.Security.Principal.NTAccount($memberName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                            } catch {
                                $sid = "UNKNOWN"
                            }
                            
                            $memberInfo = @{
                                Name = $memberName
                                SID = $sid
                                ObjectClass = "Unknown"
                                PrincipalSource = "Local"
                            }
                            $members += $memberInfo
                        }
                    }
                }
            }
        }
    } catch {
        Write-Warning "Failed to get members for group $GroupName : $($_.Exception.Message)"
    }
    
    return $members
}

# Function to check if group exists
function Test-LocalGroup {
    param(
        [string]$GroupName
    )
    
    try {
        if (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) {
            $null = Get-LocalGroup -Name $GroupName -ErrorAction Stop
            return $true
        } else {
            # Fallback method
            $output = net localgroup "$GroupName" 2>$null
            return ($LASTEXITCODE -eq 0)
        }
    } catch {
        return $false
    }
}

# Collect group membership data
foreach ($groupName in $targetGroups) {
    if (Test-LocalGroup -GroupName $groupName) {
        $members = Get-LocalGroupMembers -GroupName $groupName
        
        if ($members.Count -gt 0) {
            $result.LocalGroups[$groupName] = $members
            $result.Summary.TotalGroups++
            $result.Summary.TotalMembers += $members.Count
            
            # Count administrators specifically
            if ($groupName -eq "Administrators") {
                $result.Summary.AdminGroupMembers = $members.Count
            }
        } else {
            # Include empty groups for completeness
            $result.LocalGroups[$groupName] = @()
            $result.Summary.TotalGroups++
        }
    }
}

# Add additional domain information if available
try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computerSystem.PartOfDomain) {
        $result.DeviceInfo.Domain = $computerSystem.Domain
        $result.DeviceInfo.DomainRole = switch ($computerSystem.DomainRole) {
            0 { "Standalone Workstation" }
            1 { "Member Workstation" }
            2 { "Standalone Server" }
            3 { "Member Server" }
            4 { "Backup Domain Controller" }
            5 { "Primary Domain Controller" }
            default { "Unknown" }
        }
    } else {
        $result.DeviceInfo.Domain = "WORKGROUP"
        $result.DeviceInfo.DomainRole = "Standalone"
    }
} catch {
    $result.DeviceInfo.Domain = "UNKNOWN"
    $result.DeviceInfo.DomainRole = "Unknown"
}

# Add current user context information
try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $result.DeviceInfo.CurrentUserSID = $currentUser.User.Value
    $result.DeviceInfo.CurrentUserName = $currentUser.Name
    $result.DeviceInfo.IsElevated = ([Security.Principal.WindowsPrincipal] $currentUser).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
} catch {
    $result.DeviceInfo.CurrentUserSID = "UNKNOWN"
    $result.DeviceInfo.CurrentUserName = $env:USERNAME
    $result.DeviceInfo.IsElevated = $false
}

# Output results
if ($OutputFormat -eq "JSON") {
    $jsonOutput = $result | ConvertTo-Json -Depth 10
    Write-Output $jsonOutput
} else {
    Write-Output $result
}

# Set exit code (0 for success)
exit 0