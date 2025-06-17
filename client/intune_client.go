// File: client/intune_client.go
// Copyright (C) 2022 SpecterOps
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package client

import (
	"context"
	
	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/models/intune"
)

// IntuneClient interface extends AzureClient with Intune-specific methods
type IntuneClient interface {
	// Device Management
	ListIntuneManagedDevices(ctx context.Context, params query.GraphParams) <-chan AzureResult[intune.ManagedDevice]
	GetIntuneDeviceCompliance(ctx context.Context, deviceId string, params query.GraphParams) <-chan AzureResult[intune.ComplianceState]
	GetIntuneDeviceConfiguration(ctx context.Context, deviceId string, params query.GraphParams) <-chan AzureResult[intune.ConfigurationState]
	
	// Script Management
	ListIntuneDeviceManagementScripts(ctx context.Context, params query.GraphParams) <-chan AzureResult[intune.DeviceManagementScript]
	ExecuteIntuneScript(ctx context.Context, deviceId string, scriptContent string, runAsAccount string) <-chan AzureResult[intune.ScriptExecution]
	GetIntuneScriptResults(ctx context.Context, scriptId string, params query.GraphParams) <-chan AzureResult[intune.ScriptResult]
	
	// Data Collection
	CollectIntuneRegistryData(ctx context.Context, deviceIds []string) <-chan AzureResult[intune.RegistryCollectionResult]
	CollectIntuneLocalGroups(ctx context.Context, deviceIds []string) <-chan AzureResult[intune.LocalGroupResult]
	CollectIntuneUserRights(ctx context.Context, deviceIds []string) <-chan AzureResult[intune.UserRightsResult]
}

// Extend the existing AzureClient interface to include Intune methods
// This would be added to the existing client/client.go file
type AzureClientWithIntune interface {
	AzureClient
	IntuneClient
}