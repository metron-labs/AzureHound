// File: enums/intune.go
// Copyright (C) 2022 SpecterOps
// Enumeration types for Intune integration

package enums

// Intune-specific Kind enumerations for data types
const (
	// Device Management
	KindAZIntuneDevice         Kind = "AZIntuneDevice"
	KindAZIntuneDeviceCompliance Kind = "AZIntuneDeviceCompliance"
	KindAZIntuneDeviceConfiguration Kind = "AZIntuneDeviceConfiguration"
	
	// Script Management
	KindAZIntuneScript         Kind = "AZIntuneScript"
	KindAZIntuneScriptExecution Kind = "AZIntuneScriptExecution"
	KindAZIntuneScriptResult   Kind = "AZIntuneScriptResult"
	
	// Data Collection Results
	KindAZIntuneRegistryData   Kind = "AZIntuneRegistryData"
	KindAZIntuneLocalGroups    Kind = "AZIntuneLocalGroups"
	KindAZIntuneUserRights     Kind = "AZIntuneUserRights"
	KindAZIntuneCompliance     Kind = "AZIntuneCompliance"
)

// Device compliance states
type ComplianceState string

const (
	ComplianceStateCompliant    ComplianceState = "compliant"
	ComplianceStateNoncompliant ComplianceState = "noncompliant"
	ComplianceStateConflict     ComplianceState = "conflict"
	ComplianceStateError        ComplianceState = "error"
	ComplianceStateUnknown      ComplianceState = "unknown"
	ComplianceStateInGracePeriod ComplianceState = "inGracePeriod"
)

// Device enrollment types
type EnrollmentType string

const (
	EnrollmentTypeUserEnrollment            EnrollmentType = "userEnrollment"
	EnrollmentTypeDeviceEnrollmentManager   EnrollmentType = "deviceEnrollmentManager"
	EnrollmentTypeAppleBulkWithUser         EnrollmentType = "appleBulkWithUser"
	EnrollmentTypeAppleBulkWithoutUser      EnrollmentType = "appleBulkWithoutUser"
	EnrollmentTypeWindowsAzureADJoin        EnrollmentType = "windowsAzureADJoin"
	EnrollmentTypeWindowsBulkUserless       EnrollmentType = "windowsBulkUserless"
	EnrollmentTypeWindowsAutoEnrollment     EnrollmentType = "windowsAutoEnrollment"
	EnrollmentTypeWindowsBulkAzureDomainJoin EnrollmentType = "windowsBulkAzureDomainJoin"
	EnrollmentTypeWindowsCoManagement        EnrollmentType = "windowsCoManagement"
)

// Script execution states
type ScriptExecutionState string

const (
	ScriptExecutionStatePending   ScriptExecutionState = "pending"
	ScriptExecutionStateRunning   ScriptExecutionState = "running"
	ScriptExecutionStateSuccess   ScriptExecutionState = "success"
	ScriptExecutionStateFailed    ScriptExecutionState = "failed"
	ScriptExecutionStateTimeout   ScriptExecutionState = "timeout"
	ScriptExecutionStateError     ScriptExecutionState = "error"
)

// Management agent types
type ManagementAgent string

const (
	ManagementAgentEAS               ManagementAgent = "eas"
	ManagementAgentMDM               ManagementAgent = "mdm"
	ManagementAgentEASMDM            ManagementAgent = "easMdm"
	ManagementAgentIntuneClient      ManagementAgent = "intuneClient"
	ManagementAgentEASIntuneClient   ManagementAgent = "easIntuneClient"
	ManagementAgentConfigurationManagerClient ManagementAgent = "configurationManagerClient"
	ManagementAgentConfigurationManagerClientMDM ManagementAgent = "configurationManagerClientMdm"
	ManagementAgentConfigurationManagerClientMDMEAS ManagementAgent = "configurationManagerClientMdmEas"
	ManagementAgentUnknown           ManagementAgent = "unknown"
	ManagementAgentJamf              ManagementAgent = "jamf"
	ManagementAgentGoogleCloudDevicePolicyController ManagementAgent = "googleCloudDevicePolicyController"
)

// Operating system types
type OperatingSystem string

const (
	OperatingSystemAndroid     OperatingSystem = "android"
	OperatingSystemIOS         OperatingSystem = "iOS"
	OperatingSystemMacOS       OperatingSystem = "macOS"
	OperatingSystemWindows     OperatingSystem = "windows"
	OperatingSystemWindowsMobile OperatingSystem = "windowsMobile"
	OperatingSystemWindowsPhone OperatingSystem = "windowsPhone"
)

// Device join types
type JoinType string

const (
	JoinTypeUnknown           JoinType = "unknown"
	JoinTypeAzureADJoined     JoinType = "azureADJoined"
	JoinTypeAzureADRegistered JoinType = "azureADRegistered"
	JoinTypeHybridAzureADJoined JoinType = "hybridAzureADJoined"
)

// Security indicator types
type SecurityIndicator string

const (
	SecurityIndicatorUACDisabled             SecurityIndicator = "UAC_DISABLED"
	SecurityIndicatorAutoAdminLogon          SecurityIndicator = "AUTO_ADMIN_LOGON"
	SecurityIndicatorSuspiciousStartupItems  SecurityIndicator = "SUSPICIOUS_STARTUP_ITEMS"
	SecurityIndicatorWeakServicePermissions  SecurityIndicator = "WEAK_SERVICE_PERMISSIONS"
	SecurityIndicatorLSAProtectionDisabled   SecurityIndicator = "LSA_PROTECTION_DISABLED"
	SecurityIndicatorRestrictedAdminDisabled SecurityIndicator = "RESTRICTED_ADMIN_DISABLED"
)

// Registry key purposes
type RegistryKeyPurpose string

const (
	RegistryKeyPurposeUACSettings          RegistryKeyPurpose = "UAC and privilege settings analysis"
	RegistryKeyPurposeLogonSettings        RegistryKeyPurpose = "Logon settings and potential backdoor detection"
	RegistryKeyPurposeLSASettings          RegistryKeyPurpose = "LSA settings for credential access analysis"
	RegistryKeyPurposePersistenceMechanisms RegistryKeyPurpose = "Identify persistence mechanisms and startup programs"
	RegistryKeyPurposeServiceConfiguration RegistryKeyPurpose = "Service configuration analysis for attack vectors"
)

// User rights assignments
type UserRight string

const (
	UserRightSeAssignPrimaryTokenPrivilege     UserRight = "SeAssignPrimaryTokenPrivilege"
	UserRightSeAuditPrivilege                  UserRight = "SeAuditPrivilege"
	UserRightSeBackupPrivilege                 UserRight = "SeBackupPrivilege"
	UserRightSeChangeNotifyPrivilege           UserRight = "SeChangeNotifyPrivilege"
	UserRightSeCreateGlobalPrivilege           UserRight = "SeCreateGlobalPrivilege"
	UserRightSeCreatePagefilePrivilege         UserRight = "SeCreatePagefilePrivilege"
	UserRightSeCreatePermanentPrivilege        UserRight = "SeCreatePermanentPrivilege"
	UserRightSeCreateSymbolicLinkPrivilege     UserRight = "SeCreateSymbolicLinkPrivilege"
	UserRightSeCreateTokenPrivilege            UserRight = "SeCreateTokenPrivilege"
	UserRightSeDebugPrivilege                  UserRight = "SeDebugPrivilege"
	UserRightSeEnableDelegationPrivilege       UserRight = "SeEnableDelegationPrivilege"
	UserRightSeImpersonatePrivilege            UserRight = "SeImpersonatePrivilege"
	UserRightSeIncreaseBasePriorityPrivilege   UserRight = "SeIncreaseBasePriorityPrivilege"
	UserRightSeIncreaseQuotaPrivilege          UserRight = "SeIncreaseQuotaPrivilege"
	UserRightSeIncreaseWorkingSetPrivilege     UserRight = "SeIncreaseWorkingSetPrivilege"
	UserRightSeLoadDriverPrivilege             UserRight = "SeLoadDriverPrivilege"
	UserRightSeLockMemoryPrivilege             UserRight = "SeLockMemoryPrivilege"
	UserRightSeMachineAccountPrivilege         UserRight = "SeMachineAccountPrivilege"
	UserRightSeManageVolumePrivilege           UserRight = "SeManageVolumePrivilege"
	UserRightSeProfileSingleProcessPrivilege  UserRight = "SeProfileSingleProcessPrivilege"
	UserRightSeRelabelPrivilege                UserRight = "SeRelabelPrivilege"
	UserRightSeRemoteShutdownPrivilege         UserRight = "SeRemoteShutdownPrivilege"
	UserRightSeRestorePrivilege                UserRight = "SeRestorePrivilege"
	UserRightSeSecurityPrivilege               UserRight = "SeSecurityPrivilege"
	UserRightSeShutdownPrivilege               UserRight = "SeShutdownPrivilege"
	UserRightSeSyncAgentPrivilege              UserRight = "SeSyncAgentPrivilege"
	UserRightSeSystemEnvironmentPrivilege      UserRight = "SeSystemEnvironmentPrivilege"
	UserRightSeSystemProfilePrivilege          UserRight = "SeSystemProfilePrivilege"
	UserRightSeSystemtimePrivilege             UserRight = "SeSystemtimePrivilege"
	UserRightSeTakeOwnershipPrivilege          UserRight = "SeTakeOwnershipPrivilege"
	UserRightSeTcbPrivilege                    UserRight = "SeTcbPrivilege"
	UserRightSeTimeZonePrivilege               UserRight = "SeTimeZonePrivilege"
	UserRightSeTrustedCredManAccessPrivilege   UserRight = "SeTrustedCredManAccessPrivilege"
	UserRightSeUndockPrivilege                 UserRight = "SeUndockPrivilege"
	UserRightSeUnsolicitedInputPrivilege       UserRight = "SeUnsolicitedInputPrivilege"
)