// File: models/intune/registry.go
// Models for parsing registry data from your PowerShell scripts

package intune

// import "time"

// type DeviceInfo struct {
// 	ComputerName  string `json:"computerName"`
// 	Domain        string `json:"domain"`
// 	User          string `json:"user"`
// 	Timestamp     string `json:"timestamp"`
// 	ScriptVersion string `json:"scriptVersion"`
// }

// type RegistryKeyData struct {
// 	Path       string                 `json:"path"`
// 	Purpose    string                 `json:"purpose"`
// 	Values     map[string]interface{} `json:"values"`
// 	Accessible bool                   `json:"accessible"`
// 	Error      string                 `json:"error,omitempty"`
// }

// type SecurityIndicators struct {
// 	UACDisabled    bool `json:"uacDisabled"`
// 	AutoAdminLogon bool `json:"autoAdminLogon"`
// }

// type CollectionSummary struct {
// 	TotalKeysChecked int `json:"totalKeysChecked"`
// 	AccessibleKeys   int `json:"accessibleKeys"`
// }

// type RegistryCollectionResult struct {
// 	DeviceInfo          DeviceInfo            `json:"deviceInfo"`
// 	RegistryData        []RegistryKeyData     `json:"registryData"`
// 	SecurityIndicators  SecurityIndicators    `json:"securityIndicators"`
// 	Summary             CollectionSummary     `json:"summary"`
// }

// // Existing models that might be needed
// type DeviceManagementScript struct {
// 	Id              string    `json:"id"`
// 	DisplayName     string    `json:"displayName"`
// 	Description     string    `json:"description"`
// 	ScriptContent   string    `json:"scriptContent"`
// 	CreatedDateTime time.Time `json:"createdDateTime"`
// 	LastModifiedDateTime time.Time `json:"lastModifiedDateTime"`
// }

// type ScriptResult struct {
// 	Id            string    `json:"id"`
// 	DeviceId      string    `json:"deviceId"`
// 	RunState      string    `json:"runState"`
// 	ResultMessage string    `json:"resultMessage"`
// 	LastStateUpdateDateTime time.Time `json:"lastStateUpdateDateTime"`
// }