// pkg/bloodhound/intune_converter.go
package bloodhound

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bloodhoundad/azurehound/v2/models/azure"
)

// IntuneToBloodHoundConverter converts Intune data to BloodHound format
type IntuneToBloodHoundConverter struct {
	TenantID     string
	DomainSuffix string
	CollectedBy  string
}

// NewIntuneToBloodHoundConverter creates a new converter instance
func NewIntuneToBloodHoundConverter(tenantID, domainSuffix, collectedBy string) *IntuneToBloodHoundConverter {
	return &IntuneToBloodHoundConverter{
		TenantID:     tenantID,
		DomainSuffix: domainSuffix,
		CollectedBy:  collectedBy,
	}
}

// ConvertDeviceSecurityAnalysis converts security analysis to BloodHound format
func (c *IntuneToBloodHoundConverter) ConvertDeviceSecurityAnalysis(analyses []azure.DeviceSecurityAnalysis) *azure.BloodHoundIntuneData {
	data := &azure.BloodHoundIntuneData{
		Meta: azure.BloodHoundMeta{
			Type:        "intune-bloodhound",
			Count:       len(analyses),
			Version:     "2.0",
			Methods:     0,
			CollectedBy: c.CollectedBy,
			CollectedAt: time.Now(),
		},
		Data: azure.BloodHoundDataWrapper{
			Computers:          []azure.Computer{},
			Users:              []azure.User{},
			Groups:             []azure.Group{},
			LocalAdmins:        []azure.LocalAdmin{},
			RemoteDesktopUsers: []azure.RemoteDesktopUser{},
			Sessions:           []azure.Session{},
		},
		ComputerDomains:    []azure.ComputerDomain{},
		Computers:          []azure.Computer{},
		Users:              []azure.User{},
		Groups:             []azure.Group{},
		LocalAdmins:        []azure.LocalAdmin{},
		RemoteDesktopUsers: []azure.RemoteDesktopUser{},
		DcomUsers:          []azure.DcomUser{},
		PSRemoteUsers:      []azure.PSRemoteUser{},
		Sessions:           []azure.Session{},
		RegistryKeys:       []azure.RegistryKey{},
	}

	// Convert each device analysis
	for _, analysis := range analyses {
		computer := c.convertDeviceToComputer(analysis)
		data.Computers = append(data.Computers, computer)
		data.Data.Computers = append(data.Data.Computers, computer)

		// Convert registry keys
		registryKeys := c.convertRegistryFindings(analysis.Device.ID, analysis.SecurityFindings)
		data.RegistryKeys = append(data.RegistryKeys, registryKeys...)

		// Convert local admin relationships (if available in future data)
		localAdmins := c.convertLocalAdmins(analysis.BloodHoundData)
		data.LocalAdmins = append(data.LocalAdmins, localAdmins...)
		data.Data.LocalAdmins = append(data.Data.LocalAdmins, localAdmins...)

		// Convert RDP users (if available in future data)
		rdpUsers := c.convertRDPUsers(analysis.BloodHoundData)
		data.RemoteDesktopUsers = append(data.RemoteDesktopUsers, rdpUsers...)
		data.Data.RemoteDesktopUsers = append(data.Data.RemoteDesktopUsers, rdpUsers...)

		// Convert sessions (if available in future data)
		sessions := c.convertSessions(analysis.BloodHoundData)
		data.Sessions = append(data.Sessions, sessions...)
		data.Data.Sessions = append(data.Data.Sessions, sessions...)

		// Add computer domain relationship
		if analysis.Device.AzureADDeviceID != "" {
			computerDomain := azure.ComputerDomain{
				ComputerSID: c.generateComputerSID(analysis.Device.AzureADDeviceID),
				DomainSID:   c.generateDomainSID(),
			}
			data.ComputerDomains = append(data.ComputerDomains, computerDomain)
		}
	}

	data.Meta.Count = len(data.Computers)
	return data
}

// convertDeviceToComputer converts an Intune device to BloodHound computer format
func (c *IntuneToBloodHoundConverter) convertDeviceToComputer(analysis azure.DeviceSecurityAnalysis) azure.Computer {
	device := analysis.Device
	computerSID := c.generateComputerSID(device.AzureADDeviceID)

	computer := azure.Computer{
		ObjectIdentifier: computerSID,
		PrimaryGroupSID:  c.generateDomainComputersSID(),
		Properties: azure.ComputerProperties{
			Name:                    device.DeviceName,
			Domain:                  c.extractDomain(device.UserPrincipalName),
			ObjectID:                device.AzureADDeviceID,
			PrimaryGroupSID:         c.generateDomainComputersSID(),
			HasLAPS:                 false, // Intune doesn't use LAPS
			LastLogon:               c.timeToUnixMilli(device.LastSyncDateTime),
			LastLogonTimestamp:      c.timeToUnixMilli(device.LastSyncDateTime),
			PwdLastSet:              c.timeToUnixMilli(device.EnrolledDateTime),
			ServicePrincipalNames:   []string{},
			Description:             fmt.Sprintf("Intune managed device - %s %s", device.Manufacturer, device.Model),
			OperatingSystem:         device.OperatingSystem,
			Enabled:                 device.ComplianceState == "compliant",
			UnconstrainedDelegation: false,
			TrustedToAuth:           false,
			SamAccountName:          device.DeviceName + "$",
			DistinguishedName:       c.generateComputerDN(device.DeviceName),
			IntuneDeviceID:          device.ID,
			ComplianceState:         device.ComplianceState,
			LastSyncDateTime:        device.LastSyncDateTime,
			RiskScore:               analysis.RiskScore,
		},
		LocalAdmins:        []azure.LocalAdminRelation{},
		RemoteDesktopUsers: []azure.RDPUsersRelation{},
		DcomUsers:          []azure.DcomUsersRelation{},
		PSRemoteUsers:      []azure.PSRemoteRelation{},
		Aces:               []azure.ACE{},
		Sessions:           []azure.SessionRelation{},
		RegistryFindings:   analysis.BloodHoundData.RegistryFindings,
		SecurityFindings:   analysis.SecurityFindings,
	}

	return computer
}

// convertRegistryFindings converts security findings to registry keys for BloodHound
func (c *IntuneToBloodHoundConverter) convertRegistryFindings(deviceID string, findings []azure.SecurityFinding) []azure.RegistryKey {
	var registryKeys []azure.RegistryKey
	computerSID := c.generateComputerSID(deviceID)

	for _, finding := range findings {
		if finding.Category == "Privilege Escalation" ||
			finding.Category == "Credential Exposure" ||
			finding.Category == "Persistence" {

			registryKey := azure.RegistryKey{
				ComputerSID:  computerSID,
				RegistryPath: c.extractRegistryPath(finding),
				ValueName:    c.extractValueName(finding),
				ValueData:    c.extractValueData(finding),
				ValueType:    "REG_DWORD", // Default type
				SecurityRisk: finding.Severity,
				AttackVector: strings.Join(finding.MITREAttack, ","),
				Properties: map[string]interface{}{
					"finding_id":      finding.ID,
					"title":           finding.Title,
					"description":     finding.Description,
					"category":        finding.Category,
					"evidence":        finding.Evidence,
					"recommendations": finding.Recommendations,
				},
			}
			registryKeys = append(registryKeys, registryKey)
		}
	}

	return registryKeys
}

// convertLocalAdmins converts BloodHound data to local admin relationships
func (c *IntuneToBloodHoundConverter) convertLocalAdmins(bhData azure.BloodHoundDeviceData) []azure.LocalAdmin {
	var localAdmins []azure.LocalAdmin
	computerSID := c.generateComputerSID(bhData.AzureDeviceID)

	if administrators, exists := bhData.LocalGroups["Administrators"]; exists {
		for _, admin := range administrators {
			localAdmin := azure.LocalAdmin{
				ObjectIdentifier: c.generateUserSID(admin),
				ObjectType:       "User",
				ComputerSID:      computerSID,
			}
			localAdmins = append(localAdmins, localAdmin)
		}
	}

	return localAdmins
}

// convertRDPUsers converts BloodHound data to RDP user relationships
func (c *IntuneToBloodHoundConverter) convertRDPUsers(bhData azure.BloodHoundDeviceData) []azure.RemoteDesktopUser {
	var rdpUsers []azure.RemoteDesktopUser
	computerSID := c.generateComputerSID(bhData.AzureDeviceID)

	if rdpGroup, exists := bhData.LocalGroups["Remote Desktop Users"]; exists {
		for _, user := range rdpGroup {
			rdpUser := azure.RemoteDesktopUser{
				ObjectIdentifier: c.generateUserSID(user),
				ObjectType:       "User",
				ComputerSID:      computerSID,
			}
			rdpUsers = append(rdpUsers, rdpUser)
		}
	}

	return rdpUsers
}

// convertSessions converts BloodHound data to session relationships
func (c *IntuneToBloodHoundConverter) convertSessions(bhData azure.BloodHoundDeviceData) []azure.Session {
	var sessions []azure.Session
	computerSID := c.generateComputerSID(bhData.AzureDeviceID)

	for _, session := range bhData.Sessions {
		bhSession := azure.Session{
			ComputerSID: computerSID,
			UserSID:     c.generateUserSID(session.UserName),
			LogonType:   session.SessionType,
		}
		sessions = append(sessions, bhSession)
	}

	return sessions
}

// Helper functions for generating SIDs and identifiers
func (c *IntuneToBloodHoundConverter) generateComputerSID(deviceID string) string {
	// Generate a consistent SID-like identifier for Intune devices
	return fmt.Sprintf("S-1-5-21-INTUNE-%s-1000", strings.ReplaceAll(deviceID, "-", "")[:12])
}

func (c *IntuneToBloodHoundConverter) generateUserSID(username string) string {
	// Generate a consistent SID-like identifier for users
	hash := c.simpleHash(username)
	return fmt.Sprintf("S-1-5-21-%s-%s-1001", c.TenantID[:8], hash[:8])
}

func (c *IntuneToBloodHoundConverter) generateDomainSID() string {
	// Generate domain SID based on tenant ID
	return fmt.Sprintf("S-1-5-21-%s", c.TenantID[:24])
}

func (c *IntuneToBloodHoundConverter) generateDomainComputersSID() string {
	// Generate Domain Computers group SID
	return fmt.Sprintf("S-1-5-21-%s-515", c.TenantID[:24])
}

func (c *IntuneToBloodHoundConverter) generateComputerDN(computerName string) string {
	return fmt.Sprintf("CN=%s,CN=Computers,DC=%s", computerName, strings.ReplaceAll(c.DomainSuffix, ".", ",DC="))
}

func (c *IntuneToBloodHoundConverter) extractDomain(upn string) string {
	if upn == "" {
		return c.DomainSuffix
	}
	parts := strings.Split(upn, "@")
	if len(parts) > 1 {
		return parts[1]
	}
	return c.DomainSuffix
}

func (c *IntuneToBloodHoundConverter) extractRegistryPath(finding azure.SecurityFinding) string {
	// Extract registry path from evidence or use default based on finding type
	for _, evidence := range finding.Evidence {
		if strings.Contains(evidence, "HKLM:") || strings.Contains(evidence, "HKEY_") {
			return evidence
		}
	}

	// Default paths based on finding ID
	switch {
	case strings.Contains(finding.ID, "UAC"):
		return "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
	case strings.Contains(finding.ID, "LOGON"):
		return "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
	case strings.Contains(finding.ID, "LSA"):
		return "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
	case strings.Contains(finding.ID, "STARTUP"):
		return "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
	default:
		return "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
	}
}

func (c *IntuneToBloodHoundConverter) extractValueName(finding azure.SecurityFinding) string {
	// Extract value name from finding ID or evidence
	switch {
	case strings.Contains(finding.ID, "UAC"):
		return "EnableLUA"
	case strings.Contains(finding.ID, "AUTO_ADMIN"):
		return "AutoAdminLogon"
	case strings.Contains(finding.ID, "LSA_PPL"):
		return "RunAsPPL"
	case strings.Contains(finding.ID, "SHELL"):
		return "Shell"
	default:
		return "Unknown"
	}
}

func (c *IntuneToBloodHoundConverter) extractValueData(finding azure.SecurityFinding) interface{} {
	// Extract value data from evidence
	for _, evidence := range finding.Evidence {
		if strings.Contains(evidence, "is set to") {
			parts := strings.Split(evidence, "is set to ")
			if len(parts) > 1 {
				value := strings.TrimSpace(parts[1])
				// Try to convert to appropriate type
				if value == "0" || value == "1" {
					if value == "0" {
						return 0
					}
					return 1
				}
				return value
			}
		}
	}
	return "Unknown"
}

func (c *IntuneToBloodHoundConverter) timeToUnixMilli(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix() * 1000
}

func (c *IntuneToBloodHoundConverter) simpleHash(input string) string {
	// Simple hash function for generating consistent identifiers
	hash := uint32(0)
	for _, char := range input {
		hash = hash*31 + uint32(char)
	}
	return fmt.Sprintf("%08x", hash)
}

// GenerateBloodHoundJSON creates a complete BloodHound JSON output
func (c *IntuneToBloodHoundConverter) GenerateBloodHoundJSON(analyses []azure.DeviceSecurityAnalysis) ([]byte, error) {
	bhData := c.ConvertDeviceSecurityAnalysis(analyses)

	// Create the final BloodHound structure
	output := map[string]interface{}{
		"meta": bhData.Meta,
		"data": map[string]interface{}{
			"computers":          bhData.Computers,
			"users":              bhData.Users,
			"groups":             bhData.Groups,
			"localadmins":        bhData.LocalAdmins,
			"remotedesktopusers": bhData.RemoteDesktopUsers,
			"dcomusers":          bhData.DcomUsers,
			"psremoteusers":      bhData.PSRemoteUsers,
			"sessions":           bhData.Sessions,
			"registrykeys":       bhData.RegistryKeys,
			"computerdomains":    bhData.ComputerDomains,
		},
	}

	return json.Marshal(output)
}
