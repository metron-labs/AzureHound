// File: models/intune/models.go
// Copyright (C) 2022 SpecterOps
// Data models for Intune integration

package intune

import (
	"time"
)

// ManagedDevice represents an Intune managed device
type ManagedDevice struct {
	Id                    string    `json:"id"`
	DeviceName           string    `json:"deviceName"`
	OperatingSystem      string    `json:"operatingSystem"`
	OSVersion            string    `json:"osVersion"`
	ComplianceState      string    `json:"complianceState"`
	LastSyncDateTime     time.Time `json:"lastSyncDateTime"`
	EnrollmentType       string    `json:"enrollmentType"`
	ManagementAgent      string    `json:"managementAgent"`
	AzureADDeviceId      string    `json:"azureADDeviceId"`
	UserPrincipalName    string    `json:"userPrincipalName"`
	DeviceEnrollmentType string    `json:"deviceEnrollmentType"`
	JoinType             string    `json:"joinType"`
}

// DeviceManagementScript represents a PowerShell script for device management
type DeviceManagementScript struct {
	Id                  string    `json:"id"`
	DisplayName         string    `json:"displayName"`
	Description         string    `json:"description"`
	ScriptContent       string    `json:"scriptContent"`
	CreatedDateTime     time.Time `json:"createdDateTime"`
	LastModifiedDateTime time.Time `json:"lastModifiedDateTime"`
	RunAsAccount        string    `json:"runAsAccount"`
	FileName            string    `json:"fileName"`
}

// ScriptExecution represents the execution of a script on a device
type ScriptExecution struct {
	Id              string    `json:"id"`
	DeviceId        string    `json:"deviceId"`
	ScriptId        string    `json:"scriptId"`
	Status          string    `json:"status"`
	StartDateTime   time.Time `json:"startDateTime"`
	EndDateTime     time.Time `json:"endDateTime"`
	ScriptName      string    `json:"scriptName"`
	RunAsAccount    string    `json:"runAsAccount"`
}

// ScriptResult represents the result of script execution
type ScriptResult struct {
	Id                        string    `json:"id"`
	DeviceId                 string    `json:"deviceId"`
	DeviceName               string    `json:"deviceName"`
	RunState                 string    `json:"runState"`
	ResultMessage            string    `json:"resultMessage"`
	ScriptOutput             string    `json:"scriptOutput"`
	ErrorCode                int       `json:"errorCode"`
	LastStateUpdateDateTime  time.Time `json:"lastStateUpdateDateTime"`
}

// ComplianceState represents device compliance information
type ComplianceState struct {
	Id                                     string    `json:"id"`
	DeviceId                              string    `json:"deviceId"`
	DeviceName                            string    `json:"deviceName"`
	ComplianceGracePeriodExpirationDateTime time.Time `json:"complianceGracePeriodExpirationDateTime"`
	State                                 string    `json:"state"`
	Version                               int       `json:"version"`
	SettingStates                         []ComplianceSettingState `json:"settingStates"`
}

// ComplianceSettingState represents individual compliance setting state
type ComplianceSettingState struct {
	Setting      string `json:"setting"`
	State        string `json:"state"`
	CurrentValue string `json:"currentValue"`
}

// ConfigurationState represents device configuration state
type ConfigurationState struct {
	Id            string    `json:"id"`
	DeviceId      string    `json:"deviceId"`
	DeviceName    string    `json:"deviceName"`
	State         string    `json:"state"`
	Version       int       `json:"version"`
	SettingStates []ConfigurationSettingState `json:"settingStates"`
	PlatformType  string    `json:"platformType"`
}

// ConfigurationSettingState represents individual configuration setting state
type ConfigurationSettingState struct {
	Setting      string `json:"setting"`
	State        string `json:"state"`
	CurrentValue string `json:"currentValue"`
}

// RegistryCollectionResult represents collected registry data from a device
type RegistryCollectionResult struct {
	DeviceInfo          DeviceInfo           `json:"deviceInfo"`
	RegistryData        []RegistryKeyData    `json:"registryData"`
	SecurityIndicators  SecurityIndicators   `json:"securityIndicators"`
	Summary             CollectionSummary    `json:"summary"`
}

// DeviceInfo contains basic device information
type DeviceInfo struct {
	ComputerName   string `json:"computerName"`
	Domain         string `json:"domain"`
	User           string `json:"user"`
	Timestamp      string `json:"timestamp"`
	ScriptVersion  string `json:"scriptVersion"`
}

// RegistryKeyData represents data from a specific registry key
type RegistryKeyData struct {
	Path       string                 `json:"path"`
	Purpose    string                 `json:"purpose"`
	Values     map[string]interface{} `json:"values"`
	Accessible bool                   `json:"accessible"`
	Error      string                 `json:"error,omitempty"`
}

// SecurityIndicators contains security-related flags from registry analysis
type SecurityIndicators struct {
	UACDisabled              bool     `json:"uacDisabled"`
	AutoAdminLogon          bool     `json:"autoAdminLogon"`
	WeakServicePermissions  bool     `json:"weakServicePermissions"`
	SuspiciousStartupItems  []string `json:"suspiciousStartupItems"`
}

// CollectionSummary provides summary information about the collection
type CollectionSummary struct {
	TotalKeysChecked    int      `json:"totalKeysChecked"`
	AccessibleKeys      int      `json:"accessibleKeys"`
	HighRiskIndicators  []string `json:"highRiskIndicators"`
}

// LocalGroupResult represents local group membership data
type LocalGroupResult struct {
	DeviceInfo    DeviceInfo             `json:"deviceInfo"`
	LocalGroups   map[string][]string    `json:"localGroups"`
	Summary       GroupCollectionSummary `json:"summary"`
}

// GroupCollectionSummary provides summary of group collection
type GroupCollectionSummary struct {
	TotalGroups       int `json:"totalGroups"`
	TotalMembers      int `json:"totalMembers"`
	AdminGroupMembers int `json:"adminGroupMembers"`
}

// UserRightsResult represents user rights assignment data
type UserRightsResult struct {
	DeviceInfo         DeviceInfo                    `json:"deviceInfo"`
	UserRights         map[string][]string          `json:"userRights"`
	RoleAssignments    []UserRoleAssignment         `json:"roleAssignments"`
	Summary            UserRightsCollectionSummary  `json:"summary"`
}

// UserRoleAssignment represents a user role assignment
type UserRoleAssignment struct {
	PrincipalId   string `json:"principalId"`
	PrincipalName string `json:"principalName"`
	RoleId        string `json:"roleId"`
	RoleName      string `json:"roleName"`
	AssignmentType string `json:"assignmentType"`
}

// UserRightsCollectionSummary provides summary of user rights collection
type UserRightsCollectionSummary struct {
	TotalRights       int `json:"totalRights"`
	TotalAssignments  int `json:"totalAssignments"`
	PrivilegedRights  int `json:"privilegedRights"`
}