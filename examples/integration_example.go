// File: examples/integration_example.go
// Example showing how to integrate Intune functionality into existing AzureHound

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bloodhoundad/azurehound/v2/client"
	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/models/intune"
)

// Example of how to use the Intune integration in AzureHound
func main() {
	// This would typically be done through the existing AzureHound CLI framework
	ctx := context.Background()
	
	// Connect to Azure (using existing AzureHound authentication)
	azClient := connectToAzure() // This would use existing AzureHound auth
	
	// Example 1: List all Intune managed devices
	fmt.Println("=== Listing Intune Managed Devices ===")
	listIntuneDevicesExample(ctx, azClient)
	
	// Example 2: Collect BloodHound data from Intune devices
	fmt.Println("\n=== Collecting BloodHound Data from Intune ===")
	collectBloodHoundDataExample(ctx, azClient)
	
	// Example 3: Execute custom script on devices
	fmt.Println("\n=== Executing Custom Scripts ===")
	executeCustomScriptExample(ctx, azClient)
}

func listIntuneDevicesExample(ctx context.Context, client client.AzureClient) {
	params := query.GraphParams{
		Filter: "operatingSystem eq 'Windows' and complianceState eq 'compliant'",
		Top:    10,
	}
	
	deviceCount := 0
	for deviceResult := range client.ListIntuneManagedDevices(ctx, params) {
		if deviceResult.Error != nil {
			fmt.Printf("Error listing devices: %v\n", deviceResult.Error)
			continue
		}
		
		device := deviceResult.Ok
		fmt.Printf("Device: %s (%s) - OS: %s %s - Compliance: %s\n",
			device.DeviceName,
			device.Id,
			device.OperatingSystem,
			device.OSVersion,
			device.ComplianceState,
		)
		deviceCount++
	}
	
	fmt.Printf("Total devices found: %d\n", deviceCount)
}

func collectBloodHoundDataExample(ctx context.Context, client client.AzureClient) {
	// Get target devices
	devices := getTargetDevices(ctx, client)
	
	// Collect registry data
	fmt.Println("Collecting registry data...")
	registryResults := client.CollectIntuneRegistryData(ctx, devices)
	
	for result := range registryResults {
		if result.Error != nil {
			fmt.Printf("Registry collection error: %v\n", result.Error)
			continue
		}
		
		registryData := result.Ok
		fmt.Printf("Registry data from %s:\n", registryData.DeviceInfo.ComputerName)
		fmt.Printf("  - Total keys checked: %d\n", registryData.Summary.TotalKeysChecked)
		fmt.Printf("  - Accessible keys: %d\n", registryData.Summary.AccessibleKeys)
		fmt.Printf("  - UAC Disabled: %t\n", registryData.SecurityIndicators.UACDisabled)
		fmt.Printf("  - Auto Admin Logon: %t\n", registryData.SecurityIndicators.AutoAdminLogon)
		fmt.Printf("  - High risk indicators: %v\n", registryData.Summary.HighRiskIndicators)
	}
	
	// Collect local groups data
	fmt.Println("Collecting local groups data...")
	localGroupsResults := client.CollectIntuneLocalGroups(ctx, devices)
	
	for result := range localGroupsResults {
		if result.Error != nil {
			fmt.Printf("Local groups collection error: %v\n", result.Error)
			continue
		}
		
		groupsData := result.Ok
		fmt.Printf("Local groups from %s:\n", groupsData.DeviceInfo.ComputerName)
		fmt.Printf("  - Total groups: %d\n", groupsData.Summary.TotalGroups)
		fmt.Printf("  - Total members: %d\n", groupsData.Summary.TotalMembers)
		fmt.Printf("  - Admin group members: %d\n", groupsData.Summary.AdminGroupMembers)
		
		if admins, exists := groupsData.LocalGroups["Administrators"]; exists {
			fmt.Printf("  - Administrators: %v\n", admins)
		}
	}
}

func executeCustomScriptExample(ctx context.Context, client client.AzureClient) {
	devices := getTargetDevices(ctx, client)
	if len(devices) == 0 {
		fmt.Println("No devices available for script execution")
		return
	}
	
	// Example custom script for additional data collection
	customScript := `
# Custom BloodHound data collection script
$result = @{
    ComputerInfo = @{
        Name = $env:COMPUTERNAME
        Domain = (Get-CimInstance Win32_ComputerSystem).Domain
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        Architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        InstallDate = (Get-CimInstance Win32_OperatingSystem).InstallDate
    }
    NetworkInfo = @{
        Adapters = @()
        Routes = @()
    }
    ProcessInfo = @{
        Services = @()
        RunningProcesses = @()
    }
}

# Collect network adapter information
try {
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        $adapter = @{
            Name = $_.Name
            InterfaceDescription = $_.InterfaceDescription
            LinkSpeed = $_.LinkSpeed
            MacAddress = $_.MacAddress
        }
        $result.NetworkInfo.Adapters += $adapter
    }
} catch {}

# Collect critical services
try {
    $criticalServices = @("Winmgmt", "BITS", "Themes", "AudioSrv", "Dhcp", "Dnscache")
    foreach ($serviceName in $criticalServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            $serviceInfo = @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status.ToString()
                StartType = $service.StartType.ToString()
            }
            $result.ProcessInfo.Services += $serviceInfo
        }
    }
} catch {}

# Collect running processes (limited to avoid large output)
try {
    Get-Process | Where-Object { $_.ProcessName -in @("lsass", "winlogon", "csrss", "smss", "services") } | ForEach-Object {
        $processInfo = @{
            Name = $_.ProcessName
            Id = $_.Id
            StartTime = if ($_.StartTime) { $_.StartTime.ToString() } else { "N/A" }
            WorkingSet = [math]::Round($_.WorkingSet64 / 1MB, 2)
        }
        $result.ProcessInfo.RunningProcesses += $processInfo
    }
} catch {}

$result | ConvertTo-Json -Depth 10
`

	// Execute on first available device
	deviceId := devices[0]
	fmt.Printf("Executing custom script on device: %s\n", deviceId)
	
	for execution := range client.ExecuteIntuneScript(ctx, deviceId, customScript, "system") {
		if execution.Error != nil {
			fmt.Printf("Script execution error: %v\n", execution.Error)
			continue
		}
		
		fmt.Printf("Script execution started: %s\n", execution.Ok.Id)
		
		// Wait for results (simplified for example)
		time.Sleep(30 * time.Second)
		
		params := query.GraphParams{}
		for result := range client.GetIntuneScriptResults(ctx, execution.Ok.Id, params) {
			if result.Error != nil {
				fmt.Printf("Error getting script results: %v\n", result.Error)
				continue
			}
			
			if result.Ok.RunState == "success" {
				fmt.Printf("Script completed successfully on %s\n", result.Ok.DeviceName)
				
				// Parse and display results
				var scriptOutput map[string]interface{}
				if err := json.Unmarshal([]byte(result.Ok.ScriptOutput), &scriptOutput); err == nil {
					prettyJSON, _ := json.MarshalIndent(scriptOutput, "", "  ")
					fmt.Printf("Script output:\n%s\n", string(prettyJSON))
				}
			} else {
				fmt.Printf("Script execution state: %s - %s\n", result.Ok.RunState, result.Ok.ResultMessage)
			}
		}
	}
}

func getTargetDevices(ctx context.Context, client client.AzureClient) []string {
	var deviceIds []string
	
	params := query.GraphParams{
		Filter: "operatingSystem eq 'Windows' and complianceState eq 'compliant'",
		Top:    5, // Limit for example
	}
	
	for deviceResult := range client.ListIntuneManagedDevices(ctx, params) {
		if deviceResult.Error != nil {
			continue
		}
		deviceIds = append(deviceIds, deviceResult.Ok.Id)
	}
	
	return deviceIds
}

// Mock function - in real implementation this would use existing AzureHound auth
func connectToAzure() client.AzureClient {
	// This would use the existing AzureHound authentication mechanism
	// For example purposes, returning nil
	return nil
}

// Example of how to modify the existing AzureHound list command
func addIntuneToListCommand() {
	// This would be added to cmd/list.go in the actual implementation
	/*
	var listIntuneCmd = &cobra.Command{
		Use:   "intune",
		Short: "Lists Intune objects",
		Long:  "Lists all Intune objects that can be collected for BloodHound analysis",
		Run: func(cmd *cobra.Command, args []string) {
			// Implementation would go here
		},
	}
	
	// Add subcommands
	listIntuneCmd.AddCommand(listIntuneDevicesCmd)
	listIntuneCmd.AddCommand(collectIntuneDataCmd)
	
	// Add to parent command
	listRootCmd.AddCommand(listIntuneCmd)
	*/
}

// Example output format for BloodHound compatibility
type BloodHoundOutput struct {
	Meta struct {
		Type    string   `json:"type"`
		Version string   `json:"version"`
		Methods []string `json:"methods"`
	} `json:"meta"`
	Data []interface{} `json:"data"`
}

func createBloodHoundOutput(intuneData []interface{}) *BloodHoundOutput {
	output := &BloodHoundOutput{}
	output.Meta.Type = "azurehound"
	output.Meta.Version = "2.x.x"
	output.Meta.Methods = []string{"az", "intune"}
	output.Data = intuneData
	
	return output
}

// Example of integrating with existing AzureHound output pipeline
func outputIntuneData(intuneData []interface{}) {
	bloodhoundOutput := createBloodHoundOutput(intuneData)
	
	// Convert to JSON
	jsonData, err := json.MarshalIndent(bloodhoundOutput, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling output: %v", err)
	}
	
	// Write to file or stdout (following existing AzureHound pattern)
	if outputFile := os.Getenv("AZUREHOUND_OUTPUT"); outputFile != "" {
		err = os.WriteFile(outputFile, jsonData, 0644)
		if err != nil {
			log.Fatalf("Error writing output file: %v", err)
		}
		fmt.Printf("Data written to %s\n", outputFile)
	} else {
		fmt.Println(string(jsonData))
	}
}