// client/intune_sessions_direct.go
package client

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/models/azure"
)

// Direct API endpoints for session data collection
const (
	// Microsoft Graph endpoints for session data
	SignInLogsEndpoint = "/auditLogs/signIns"
	DevicesEndpoint    = "/devices"
	UsersEndpoint      = "/users"
	GroupsEndpoint     = "/groups"

	// Azure AD endpoints for enhanced session data
	DirectoryAuditEndpoint = "/auditLogs/directoryAudits"
	RiskDetectionsEndpoint = "/identityProtection/riskDetections"
)

// SignInEvent represents a sign-in event from Microsoft Graph
type SignInEvent struct {
	ID                    string    `json:"id"`
	CreatedDateTime       time.Time `json:"createdDateTime"`
	UserDisplayName       string    `json:"userDisplayName"`
	UserPrincipalName     string    `json:"userPrincipalName"`
	UserId                string    `json:"userId"`
	AppDisplayName        string    `json:"appDisplayName"`
	ClientAppUsed         string    `json:"clientAppUsed"`
	IPAddress             string    `json:"ipAddress"`
	IsInteractive         bool      `json:"isInteractive"`
	ResourceDisplayName   string    `json:"resourceDisplayName"`
	RiskState             string    `json:"riskState"`
	RiskLevelAggregated   string    `json:"riskLevelAggregated"`
	RiskLevelDuringSignIn string    `json:"riskLevelDuringSignIn"`
}

type SignInStatus struct {
	ErrorCode         int    `json:"errorCode"`
	FailureReason     string `json:"failureReason"`
	AdditionalDetails string `json:"additionalDetails"`
}

type DeviceDetail struct {
	DeviceId        string `json:"deviceId"`
	DisplayName     string `json:"displayName"`
	OperatingSystem string `json:"operatingSystem"`
	Browser         string `json:"browser"`
	IsCompliant     bool   `json:"isCompliant"`
	IsManaged       bool   `json:"isManaged"`
	TrustType       string `json:"trustType"`
}

type SignInLocation struct {
	City            string         `json:"city"`
	State           string         `json:"state"`
	CountryOrRegion string         `json:"countryOrRegion"`
	GeoCoordinates  GeoCoordinates `json:"geoCoordinates"`
}

type GeoCoordinates struct {
	Altitude  float64 `json:"altitude"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

type SessionPolicy struct {
	ExpirationRequirement string `json:"expirationRequirement"`
	Detail                string `json:"detail"`
}

// CollectSessionDataDirectly - placeholder implementation that works with existing code
func (s *azureClient) CollectSessionDataDirectly(ctx context.Context) <-chan AzureResult[azure.DeviceSessionData] {
	out := make(chan AzureResult[azure.DeviceSessionData])

	go func() {
		defer close(out)

		log.Printf("Collecting session data via Graph API (placeholder implementation)...")

		// Get list of devices first
		devices := s.ListIntuneDevices(ctx, query.GraphParams{})

		for deviceResult := range devices {
			if deviceResult.Error != nil {
				log.Printf("Error listing device: %v", deviceResult.Error)
				continue
			}

			device := deviceResult.Ok

			// Only process Windows devices
			if !strings.Contains(strings.ToLower(device.OperatingSystem), "windows") {
				continue
			}

			// Generate session data based on device properties
			sessionData := generateSessionDataFromDevice(device)

			deviceSessionData := azure.DeviceSessionData{
				Device:      device,
				SessionData: sessionData,
				CollectedAt: time.Now(),
			}

			out <- AzureResult[azure.DeviceSessionData]{Ok: deviceSessionData}
		}
	}()

	return out
}

// GetUserSignInActivity - placeholder implementation
func (s *azureClient) GetUserSignInActivity(ctx context.Context, userPrincipalName string, days int) ([]SignInEvent, error) {
	// This would query the actual Graph API in a full implementation
	log.Printf("Getting sign-in activity for user %s (placeholder)", userPrincipalName)
	return []SignInEvent{}, nil
}

// GetDeviceSignInActivity - placeholder implementation
func (s *azureClient) GetDeviceSignInActivity(ctx context.Context, deviceId string, days int) ([]SignInEvent, error) {
	// This would query the actual Graph API in a full implementation
	log.Printf("Getting sign-in activity for device %s (placeholder)", deviceId)
	return []SignInEvent{}, nil
}

// Helper function to generate session data from device info
func generateSessionDataFromDevice(device azure.IntuneDevice) azure.SessionData {
	now := time.Now()

	// Extract username from UPN
	userName := "Unknown"
	if device.UserPrincipalName != "" {
		parts := strings.Split(device.UserPrincipalName, "@")
		if len(parts) > 0 {
			userName = parts[0]
		}
	}

	// Determine if user is admin based on name
	isElevated := strings.Contains(strings.ToLower(userName), "admin") ||
		strings.Contains(strings.ToLower(device.UserDisplayName), "admin")

	sessionData := azure.SessionData{
		DeviceInfo: azure.DeviceInfo{
			ComputerName:  device.DeviceName,
			Domain:        "AZUREAD",
			User:          "SYSTEM",
			Timestamp:     now.Format(time.RFC3339),
			ScriptVersion: "graph-api-placeholder-1.0",
		},
		ActiveSessions: []azure.ActiveSession{},
		LoggedOnUsers:  []azure.LoggedOnUser{},
		SecurityIndicators: azure.SessionSecurityInfo{
			AdminSessionsActive:     false,
			RemoteSessionsActive:    false,
			ServiceAccountSessions:  false,
			CredentialTheftRisk:     "Low",
			PrivilegeEscalationRisk: "Low",
			SuspiciousActivities:    []azure.SuspiciousActivity{},
		},
		Summary: azure.SessionDataSummary{
			TotalActiveSessions: 0,
			UniqueUsers:         0,
			AdminSessions:       0,
			RemoteSessions:      0,
			ServiceSessions:     0,
			CredentialExposure:  0,
		},
	}

	// Only add session data if we have a user
	if userName != "Unknown" {
		session := azure.ActiveSession{
			SessionID:     1,
			UserName:      userName,
			DomainName:    "AZUREAD",
			SessionType:   "Console",
			SessionState:  "Active",
			LogonTime:     device.LastSyncDateTime,
			IdleTime:      "00:00:00",
			ClientName:    device.DeviceName,
			ClientAddress: "127.0.0.1",
			ProcessCount:  0,
			IsElevated:    isElevated,
		}
		sessionData.ActiveSessions = append(sessionData.ActiveSessions, session)

		user := azure.LoggedOnUser{
			UserName:         userName,
			DomainName:       "AZUREAD",
			SID:              fmt.Sprintf("S-1-12-1-%d", now.Unix()),
			LogonType:        "Interactive",
			AuthPackage:      "AzureAD",
			LogonTime:        device.LastSyncDateTime,
			LogonServer:      "login.microsoftonline.com",
			HasCachedCreds:   true,
			IsServiceAccount: false,
			TokenPrivileges:  []string{},
		}
		sessionData.LoggedOnUsers = append(sessionData.LoggedOnUsers, user)

		// Update summary
		sessionData.Summary.TotalActiveSessions = 1
		sessionData.Summary.UniqueUsers = 1
		sessionData.Summary.CredentialExposure = 1

		if isElevated {
			sessionData.Summary.AdminSessions = 1
			sessionData.SecurityIndicators.AdminSessionsActive = true
			sessionData.SecurityIndicators.CredentialTheftRisk = "Medium"
		}
	}

	return sessionData
}
