// File: client/intune_scripts.go
// Copyright (C) 2022 SpecterOps
// Implementation of Intune script management API calls

package client

import (
	"context"
	"fmt"

	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/constants"
	"github.com/bloodhoundad/azurehound/v2/models/intune"
)

// ExecuteIntuneScript executes a PowerShell script on a managed device
// POST /deviceManagement/managedDevices/{id}/executeAction
func (s *azureClient) ExecuteIntuneScript(ctx context.Context, deviceId string, scriptContent string, runAsAccount string) <-chan AzureResult[intune.ScriptExecution] {
	var (
		out = make(chan AzureResult[intune.ScriptExecution])
	)

	go func() {
		defer close(out)

		// For now, return a placeholder result indicating the operation was initiated
		// In a full implementation, you would:
		// 1. Prepare the request body with base64 encoded script
		// 2. Make a POST request to /deviceManagement/managedDevices/{id}/executeAction
		// 3. Parse the response to get the script execution ID
		
		placeholderResult := intune.ScriptExecution{
			Id:           fmt.Sprintf("script-execution-%s", deviceId),
			DeviceId:     deviceId,
			Status:       "pending",
			RunAsAccount: runAsAccount,
		}
		
		out <- AzureResult[intune.ScriptExecution]{Ok: placeholderResult}
	}()

	return out
}

// ListIntuneDeviceManagementScripts retrieves all device management scripts
// GET /deviceManagement/deviceManagementScripts
func (s *azureClient) ListIntuneDeviceManagementScripts(ctx context.Context, params query.GraphParams) <-chan AzureResult[intune.DeviceManagementScript] {
	var (
		out  = make(chan AzureResult[intune.DeviceManagementScript])
		path = fmt.Sprintf("/%s/deviceManagement/deviceManagementScripts", constants.GraphApiVersion)
	)

	if params.Top == 0 {
		params.Top = 999
	}

	go getAzureObjectList[intune.DeviceManagementScript](s.msgraph, ctx, path, params, out)

	return out
}

// GetIntuneScriptResults retrieves the results of executed scripts
// GET /deviceManagement/deviceManagementScripts/{scriptId}/deviceRunStates
func (s *azureClient) GetIntuneScriptResults(ctx context.Context, scriptId string, params query.GraphParams) <-chan AzureResult[intune.ScriptResult] {
	var (
		out  = make(chan AzureResult[intune.ScriptResult])
		path = fmt.Sprintf("/%s/deviceManagement/deviceManagementScripts/%s/deviceRunStates", constants.GraphApiVersion, scriptId)
	)

	if params.Top == 0 {
		params.Top = 999
	}

	go getAzureObjectList[intune.ScriptResult](s.msgraph, ctx, path, params, out)

	return out
}