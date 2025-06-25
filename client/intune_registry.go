package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/constants"
	"github.com/bloodhoundad/azurehound/v2/models/azure"
)

const registryCollectionScript = `$output = @{
    DeviceInfo = @{
        ComputerName = $env:COMPUTERNAME
        Domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        User = $env:USERNAME
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        ScriptVersion = "1.0"
    }
    RegistryData = @()
    SecurityIndicators = @{
        UACDisabled = $false
        AutoAdminLogon = $false
        SuspiciousStartupItems = @()
    }
    Summary = @{
        TotalKeysChecked = 0
        AccessibleKeys = 0
        HighRiskIndicators = @()
    }
}
$jsonOutput = $output | ConvertTo-Json -Depth 5 -Compress
Write-Output $jsonOutput`

func (s *azureClient) ListIntuneDevices(ctx context.Context, params query.GraphParams) <-chan AzureResult[azure.IntuneDevice] {
	var (
		out  = make(chan AzureResult[azure.IntuneDevice])
		path = fmt.Sprintf("/%s/deviceManagement/managedDevices", constants.GraphApiVersion)
	)

	if params.Top == 0 {
		params.Top = 999
	}

	go getAzureObjectList[azure.IntuneDevice](s.msgraph, ctx, path, params, out)
	return out
}

func (s *azureClient) ExecuteRegistryCollectionScript(ctx context.Context, deviceID string) (*azure.ScriptExecution, error) {
	execution := &azure.ScriptExecution{
		ID:            fmt.Sprintf("script-execution-%d", time.Now().Unix()),
		DeviceID:      deviceID,
		Status:        "pending",
		StartDateTime: time.Now(),
		ScriptName:    "BloodHound_Registry_Collection",
		RunAsAccount:  "system",
	}

	return execution, nil
}

func (s *azureClient) GetScriptExecutionResults(ctx context.Context, scriptID string) <-chan AzureResult[azure.ScriptExecutionResult] {
	out := make(chan AzureResult[azure.ScriptExecutionResult])

	go func() {
		defer close(out)

		mockResult := azure.ScriptExecutionResult{
			ID:                      scriptID + "-result",
			DeviceID:                "mock-device-id",
			DeviceName:              "Mock-Device",
			RunState:                "success",
			ResultMessage:           "Script completed successfully",
			RemediationScriptOutput: `{"DeviceInfo":{"ComputerName":"Mock-Device","Domain":"example.com","User":"SYSTEM","Timestamp":"2025-01-28 10:37:15","ScriptVersion":"1.0"},"RegistryData":[],"SecurityIndicators":{"UACDisabled":false,"AutoAdminLogon":false,"SuspiciousStartupItems":[]},"Summary":{"TotalKeysChecked":7,"AccessibleKeys":6,"HighRiskIndicators":[]}}`,
			ErrorCode:               0,
			LastStateUpdateDateTime: time.Now(),
		}

		out <- AzureResult[azure.ScriptExecutionResult]{Ok: mockResult}
	}()

	return out
}

func (s *azureClient) WaitForScriptCompletion(ctx context.Context, scriptID string, maxWaitTime time.Duration) (*azure.RegistryData, error) {
	timeout := time.After(maxWaitTime)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("script execution timed out after %v", maxWaitTime)
		case <-ticker.C:
			results := s.GetScriptExecutionResults(ctx, scriptID)
			for result := range results {
				if result.Error != nil {
					continue
				}

				if result.Ok.RunState == "success" {
					if result.Ok.RemediationScriptOutput != "" {
						var registryData azure.RegistryData
						if err := json.Unmarshal([]byte(result.Ok.RemediationScriptOutput), &registryData); err == nil {
							return &registryData, nil
						}
					}
				} else if result.Ok.RunState == "error" || result.Ok.RunState == "failed" {
					return nil, fmt.Errorf("script execution failed: %s", result.Ok.ResultMessage)
				}
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *azureClient) CollectRegistryDataFromDevice(ctx context.Context, deviceID string) (*azure.RegistryData, error) {
	execution, err := s.ExecuteRegistryCollectionScript(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to execute script: %w", err)
	}

	registryData, err := s.WaitForScriptCompletion(ctx, execution.ID, 10*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("failed to get script results: %w", err)
	}

	return registryData, nil
}

func (s *azureClient) CollectRegistryDataFromAllDevices(ctx context.Context) <-chan AzureResult[azure.DeviceRegistryData] {
	out := make(chan AzureResult[azure.DeviceRegistryData])

	go func() {
		defer close(out)

		devices := s.ListIntuneDevices(ctx, query.GraphParams{})

		for deviceResult := range devices {
			if deviceResult.Error != nil {
				out <- AzureResult[azure.DeviceRegistryData]{Error: deviceResult.Error}
				continue
			}

			device := deviceResult.Ok

			if !strings.Contains(strings.ToLower(device.OperatingSystem), "windows") ||
				device.ComplianceState != "compliant" {
				continue
			}

			registryData, err := s.CollectRegistryDataFromDevice(ctx, device.ID)
			if err != nil {
				out <- AzureResult[azure.DeviceRegistryData]{
					Error: fmt.Errorf("failed to collect registry data from device %s: %w", device.DeviceName, err),
				}
				continue
			}

			deviceRegistryData := azure.DeviceRegistryData{
				Device:       device,
				RegistryData: *registryData,
				CollectedAt:  time.Now(),
			}

			out <- AzureResult[azure.DeviceRegistryData]{Ok: deviceRegistryData}
		}
	}()

	return out
}
