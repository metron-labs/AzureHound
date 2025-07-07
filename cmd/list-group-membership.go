// cmd/list-group-membership.go
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bloodhoundad/azurehound/v2/client"
	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/models/azure"
	"github.com/spf13/cobra"
)

func init() {
	listRootCmd.AddCommand(listGroupMembershipCmd)
}

var listGroupMembershipCmd = &cobra.Command{
	Use:          "group-membership",
	Long:         "Collects Azure AD group membership and user role assignment data via Graph API",
	Run:          listGroupMembershipCmdImpl,
	SilenceUsage: true,
}

func listGroupMembershipCmdImpl(cmd *cobra.Command, args []string) {
	ctx, stop := context.WithCancel(cmd.Context())
	defer stop()

	azClient := connectAndCreateClient()

	fmt.Printf("🚀 Starting Azure AD data collection via Graph API...\n\n")
	startTime := time.Now()

	// Collect all data in parallel
	result, err := collectAllGraphData(ctx, azClient)
	if err != nil {
		exit(err)
	}

	duration := time.Since(startTime)
	result.CollectionTime = duration

	// Display results
	displayGraphDataResults(result)

	// Export to BloodHound format
	err = exportGraphDataToBloodHound(result)
	if err != nil {
		fmt.Printf("⚠️  Warning: Failed to export BloodHound data: %v\n", err)
	}
}

func collectAllGraphData(ctx context.Context, azClient client.AzureClient) (*azure.GraphDataCollectionResult, error) {
	result := &azure.GraphDataCollectionResult{
		GroupMemberships:    []azure.GroupMembershipData{},
		UserRoleAssignments: []azure.UserRoleData{},
		DeviceAccess:        []azure.DeviceAccessData{},
		SignInActivity:      []azure.SignIn{},
		Errors:              []string{},
	}

	// Collect Group Memberships
	fmt.Printf("👥 Collecting Azure AD groups and memberships...\n")
	groupResults := azClient.CollectGroupMembershipData(ctx)
	for groupResult := range groupResults {
		if groupResult.Error != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Group error: %v", groupResult.Error))
		} else {
			result.GroupMemberships = append(result.GroupMemberships, groupResult.Ok)
			result.TotalGroups++
		}
	}
	fmt.Printf("   ✅ Collected %d groups\n", result.TotalGroups)

	// Collect User Role Assignments
	fmt.Printf("🔑 Collecting user role assignments...\n")
	userResults := azClient.CollectUserRoleAssignments(ctx)
	for userResult := range userResults {
		if userResult.Error != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("User error: %v", userResult.Error))
		} else {
			result.UserRoleAssignments = append(result.UserRoleAssignments, userResult.Ok)
			result.TotalUsers++
		}
	}
	fmt.Printf("   ✅ Collected role assignments for %d users\n", result.TotalUsers)

	// Collect Device Access Data
	fmt.Printf("💻 Collecting device access and ownership data...\n")
	deviceResults := azClient.CollectDeviceAccessData(ctx)
	for deviceResult := range deviceResults {
		if deviceResult.Error != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Device error: %v", deviceResult.Error))
		} else {
			result.DeviceAccess = append(result.DeviceAccess, deviceResult.Ok)
			result.TotalDevices++
		}
	}
	fmt.Printf("   ✅ Collected access data for %d devices\n", result.TotalDevices)

	// Collect Recent Sign-in Activity (optional - can be large dataset)
	fmt.Printf("📊 Collecting recent sign-in activity (last 24 hours)...\n")
	signInResults := azClient.ListSignIns(ctx, query.GraphParams{
		Filter: fmt.Sprintf("createdDateTime ge %s", time.Now().Add(-24*time.Hour).Format("2006-01-02T15:04:05Z")),
		Top:    1000, // Limit to avoid overwhelming results
	})
	for signInResult := range signInResults {
		if signInResult.Error != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Sign-in error: %v", signInResult.Error))
		} else {
			result.SignInActivity = append(result.SignInActivity, signInResult.Ok)
			result.TotalSignIns++
		}
	}
	fmt.Printf("   ✅ Collected %d sign-in events\n", result.TotalSignIns)

	return result, nil
}

func displayGraphDataResults(result *azure.GraphDataCollectionResult) {
	fmt.Printf("\n=== AZURE AD DATA COLLECTION RESULTS ===\n")
	fmt.Printf("⏱️  Collection Time: %v\n", result.CollectionTime)
	fmt.Printf("📊 Data Summary:\n")
	fmt.Printf("   • Groups: %d\n", result.TotalGroups)
	fmt.Printf("   • Users: %d\n", result.TotalUsers)
	fmt.Printf("   • Devices: %d\n", result.TotalDevices)
	fmt.Printf("   • Sign-ins: %d\n", result.TotalSignIns)
	fmt.Printf("   • Errors: %d\n", len(result.Errors))
	fmt.Printf("\n")

	// Group Analysis
	if len(result.GroupMemberships) > 0 {
		fmt.Printf("👥 GROUP MEMBERSHIP ANALYSIS:\n")

		totalMembers := 0
		privilegedGroups := 0

		for _, group := range result.GroupMemberships {
			totalMembers += len(group.Members)

			// Check for privileged groups
			groupName := group.Group.DisplayName
			if isPrivilegedGroup(groupName) {
				privilegedGroups++
				fmt.Printf("   🔴 Privileged Group: %s (%d members)\n", groupName, len(group.Members))
			}
		}

		fmt.Printf("   • Total Group Memberships: %d\n", totalMembers)
		fmt.Printf("   • Privileged Groups Found: %d\n", privilegedGroups)
		fmt.Printf("\n")
	}

	// User Rights Analysis
	if len(result.UserRoleAssignments) > 0 {
		fmt.Printf("🔑 USER RIGHTS ANALYSIS:\n")

		totalAssignments := 0
		privilegedUsers := 0

		for _, user := range result.UserRoleAssignments {
			totalAssignments += len(user.RoleAssignments)

			if hasPrivilegedRoles(user.RoleAssignments) {
				privilegedUsers++
				fmt.Printf("   🔴 Privileged User: %s (%d roles)\n",
					user.User.DisplayName, len(user.RoleAssignments))
			}
		}

		fmt.Printf("   • Total Role Assignments: %d\n", totalAssignments)
		fmt.Printf("   • Users with Privileged Roles: %d\n", privilegedUsers)
		fmt.Printf("\n")
	}

	// Device Access Analysis
	if len(result.DeviceAccess) > 0 {
		fmt.Printf("💻 DEVICE ACCESS ANALYSIS:\n")

		devicesWithOwners := 0
		totalOwners := 0

		for _, device := range result.DeviceAccess {
			if len(device.RegisteredOwners) > 0 {
				devicesWithOwners++
				totalOwners += len(device.RegisteredOwners)
			}
		}

		fmt.Printf("   • Devices with Registered Owners: %d/%d\n", devicesWithOwners, len(result.DeviceAccess))
		fmt.Printf("   • Total Device Owners: %d\n", totalOwners)
		fmt.Printf("\n")
	}

	// Error Summary
	if len(result.Errors) > 0 {
		fmt.Printf("⚠️  ERRORS ENCOUNTERED:\n")
		for i, err := range result.Errors {
			if i >= 10 { // Limit error display
				fmt.Printf("   ... and %d more errors\n", len(result.Errors)-10)
				break
			}
			fmt.Printf("   • %s\n", err)
		}
		fmt.Printf("\n")
	}
}

func exportGraphDataToBloodHound(result *azure.GraphDataCollectionResult) error {
	fmt.Printf("📤 Exporting data to BloodHound format...\n")

	bloodhoundData := convertToBloodHoundFormat(result)

	// Write to file
	filename := fmt.Sprintf("bloodhound_azuread_graph_%s.json", time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create export file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(bloodhoundData); err != nil {
		return fmt.Errorf("failed to write BloodHound data: %w", err)
	}

	fmt.Printf("✅ BloodHound data exported to: %s\n", filename)
	fmt.Printf("   • Users: %d\n", len(bloodhoundData.Data.Users))
	fmt.Printf("   • Groups: %d\n", len(bloodhoundData.Data.Groups))
	fmt.Printf("   • Devices: %d\n", len(bloodhoundData.Data.Devices))
	fmt.Printf("   • Group Memberships: %d\n", len(bloodhoundData.GroupMemberships))
	fmt.Printf("   • Role Assignments: %d\n", len(bloodhoundData.UserRoleAssignments))
	fmt.Printf("   • Device Ownerships: %d\n", len(bloodhoundData.DeviceOwnerships))

	return nil
}

func convertToBloodHoundFormat(result *azure.GraphDataCollectionResult) azure.BloodHoundGraphData {
	bloodhoundData := azure.BloodHoundGraphData{
		Meta: azure.BloodHoundMeta{
			Type:        "azuread-graph",
			Count:       result.TotalGroups + result.TotalUsers + result.TotalDevices,
			Version:     "1.0",
			Methods:     4, // Groups, Users, Devices, Sign-ins
			CollectedBy: "AzureHound-Graph",
			CollectedAt: time.Now(),
		},
		GroupMemberships:    []azure.BloodHoundGroupMembership{},
		UserRoleAssignments: []azure.BloodHoundUserRoleAssignment{},
		DeviceOwnerships:    []azure.BloodHoundDeviceOwnership{},
		SignInActivity:      []azure.BloodHoundSignInActivity{},
	}

	var users []azure.BloodHoundUser
	var groups []azure.BloodHoundGroup
	var devices []azure.BloodHoundDevice

	// Convert Groups and Memberships
	for _, groupData := range result.GroupMemberships {
		// Convert group - fix field name from ID to Id
		group := azure.BloodHoundGroup{
			ObjectIdentifier: groupData.Group.Id,
			Properties: azure.BloodHoundGroupProperties{
				Name:              groupData.Group.DisplayName,
				Domain:            extractDomainFromGroup(groupData.Group),
				ObjectID:          groupData.Group.Id,
				Description:       groupData.Group.Description,
				SamAccountName:    groupData.Group.DisplayName,
				DistinguishedName: fmt.Sprintf("CN=%s", groupData.Group.DisplayName),
			},
		}
		groups = append(groups, group)

		// Convert memberships
		for _, memberRaw := range groupData.Members {
			var member map[string]interface{}
			json.Unmarshal(memberRaw, &member)

			if memberID, ok := member["id"].(string); ok {
				memberName := ""
				memberType := "User"

				if displayName, ok := member["displayName"].(string); ok {
					memberName = displayName
				}
				if odataType, ok := member["@odata.type"].(string); ok {
					memberType = extractTypeFromOData(odataType)
				}

				membership := azure.BloodHoundGroupMembership{
					GroupId:          groupData.Group.Id,
					GroupName:        groupData.Group.DisplayName,
					MemberId:         memberID,
					MemberName:       memberName,
					MemberType:       memberType,
					RelationshipType: "MemberOf",
				}
				bloodhoundData.GroupMemberships = append(bloodhoundData.GroupMemberships, membership)
			}
		}

		// Convert owners
		for _, ownerRaw := range groupData.Owners {
			var owner map[string]interface{}
			json.Unmarshal(ownerRaw, &owner)

			if ownerID, ok := owner["id"].(string); ok {
				ownerName := ""
				ownerType := "User"

				if displayName, ok := owner["displayName"].(string); ok {
					ownerName = displayName
				}
				if odataType, ok := owner["@odata.type"].(string); ok {
					ownerType = extractTypeFromOData(odataType)
				}

				ownership := azure.BloodHoundGroupMembership{
					GroupId:          groupData.Group.Id,
					GroupName:        groupData.Group.DisplayName,
					MemberId:         ownerID,
					MemberName:       ownerName,
					MemberType:       ownerType,
					RelationshipType: "OwnerOf",
				}
				bloodhoundData.GroupMemberships = append(bloodhoundData.GroupMemberships, ownership)
			}
		}
	}

	// Convert Users and Role Assignments
	for _, userData := range result.UserRoleAssignments {
		// Convert user - fix field name from ID to Id
		user := azure.BloodHoundUser{
			ObjectIdentifier: userData.User.Id,
			Properties: azure.BloodHoundUserProperties{
				Name:                    userData.User.DisplayName,
				Domain:                  extractDomainFromUPN(userData.User.UserPrincipalName),
				ObjectID:                userData.User.Id,
				DisplayName:             userData.User.DisplayName,
				Email:                   userData.User.UserPrincipalName,
				Enabled:                 userData.User.AccountEnabled,
				SamAccountName:          userData.User.UserPrincipalName,
				DistinguishedName:       fmt.Sprintf("CN=%s", userData.User.DisplayName),
				UnconstrainedDelegation: false,
				Sensitive:               false,
			},
		}
		users = append(users, user)

		// Convert role assignments
		for _, assignment := range userData.RoleAssignments {
			roleAssignment := azure.BloodHoundUserRoleAssignment{
				UserId:          userData.User.Id,
				UserName:        userData.User.DisplayName,
				RoleId:          assignment.AppRoleId.String(), // Convert UUID to string
				RoleName:        assignment.PrincipalDisplayName,
				ResourceId:      assignment.ResourceId,
				ResourceName:    assignment.ResourceDisplayName,
				AssignmentType:  "DirectAssignment",
				CreatedDateTime: time.Now(),
			}
			bloodhoundData.UserRoleAssignments = append(bloodhoundData.UserRoleAssignments, roleAssignment)
		}
	}

	// Convert Devices and Ownership
	for _, deviceData := range result.DeviceAccess {
		// Convert device - IntuneDevice uses ID (uppercase)
		device := azure.BloodHoundDevice{
			ObjectIdentifier: deviceData.IntuneDevice.ID,
			Properties: azure.BloodHoundDeviceProperties{
				Name:             deviceData.IntuneDevice.DeviceName,
				DisplayName:      deviceData.IntuneDevice.DeviceName,
				ObjectID:         deviceData.IntuneDevice.ID,
				OperatingSystem:  deviceData.IntuneDevice.OperatingSystem,
				OSVersion:        deviceData.IntuneDevice.OSVersion,
				DeviceId:         deviceData.IntuneDevice.AzureADDeviceID,
				IsCompliant:      deviceData.IntuneDevice.ComplianceState == "compliant",
				IsManaged:        true,
				EnrollmentType:   deviceData.IntuneDevice.EnrollmentType,
				LastSyncDateTime: deviceData.IntuneDevice.LastSyncDateTime,
				Enabled:          true,
			},
		}

		// Add registered users
		for _, userRaw := range deviceData.RegisteredUsers {
			var user map[string]interface{}
			json.Unmarshal(userRaw, &user)

			if userID, ok := user["id"].(string); ok {
				deviceUser := azure.BloodHoundDeviceUser{
					ObjectIdentifier: userID,
					ObjectType:       "User",
				}
				device.RegisteredUsers = append(device.RegisteredUsers, deviceUser)

				// Create ownership relationship
				userName := ""
				if displayName, ok := user["displayName"].(string); ok {
					userName = displayName
				}

				ownership := azure.BloodHoundDeviceOwnership{
					DeviceId:        deviceData.IntuneDevice.ID,
					DeviceName:      deviceData.IntuneDevice.DeviceName,
					UserId:          userID,
					UserName:        userName,
					OwnershipType:   "RegisteredUser",
					ComplianceState: deviceData.IntuneDevice.ComplianceState,
				}
				bloodhoundData.DeviceOwnerships = append(bloodhoundData.DeviceOwnerships, ownership)
			}
		}

		// Add registered owners
		for _, ownerRaw := range deviceData.RegisteredOwners {
			var owner map[string]interface{}
			json.Unmarshal(ownerRaw, &owner)

			if ownerID, ok := owner["id"].(string); ok {
				deviceOwner := azure.BloodHoundDeviceUser{
					ObjectIdentifier: ownerID,
					ObjectType:       "User",
				}
				device.RegisteredOwners = append(device.RegisteredOwners, deviceOwner)

				// Create ownership relationship
				ownerName := ""
				if displayName, ok := owner["displayName"].(string); ok {
					ownerName = displayName
				}

				ownership := azure.BloodHoundDeviceOwnership{
					DeviceId:        deviceData.IntuneDevice.ID,
					DeviceName:      deviceData.IntuneDevice.DeviceName,
					UserId:          ownerID,
					UserName:        ownerName,
					OwnershipType:   "RegisteredOwner",
					ComplianceState: deviceData.IntuneDevice.ComplianceState,
				}
				bloodhoundData.DeviceOwnerships = append(bloodhoundData.DeviceOwnerships, ownership)
			}
		}

		devices = append(devices, device)
	}

	// Convert Sign-in Activity
	for _, signIn := range result.SignInActivity {
		signInActivity := azure.BloodHoundSignInActivity{
			UserId:            signIn.UserId,
			UserName:          signIn.UserDisplayName,
			DeviceId:          signIn.DeviceDetail.DeviceId,
			DeviceName:        signIn.DeviceDetail.DisplayName,
			AppId:             signIn.AppId,
			AppName:           signIn.AppDisplayName,
			SignInDateTime:    signIn.CreatedDateTime,
			IpAddress:         signIn.IpAddress,
			Location:          fmt.Sprintf("%s, %s", signIn.Location.City, signIn.Location.CountryOrRegion),
			RiskLevel:         signIn.RiskLevelAggregated,
			ConditionalAccess: signIn.ConditionalAccessStatus,
		}
		bloodhoundData.SignInActivity = append(bloodhoundData.SignInActivity, signInActivity)
	}

	// Set data wrapper
	bloodhoundData.Data = azure.BloodHoundGraphDataWrapper{
		Users:   users,
		Groups:  groups,
		Devices: devices,
	}

	return bloodhoundData
}

// Helper functions
func isPrivilegedGroup(groupName string) bool {
	privilegedGroups := []string{
		"Global Administrator",
		"Privileged Role Administrator",
		"Security Administrator",
		"User Administrator",
		"Exchange Administrator",
		"SharePoint Administrator",
		"Application Administrator",
		"Cloud Application Administrator",
		"Authentication Administrator",
		"Privileged Authentication Administrator",
		"Domain Admins",
		"Enterprise Admins",
		"Schema Admins",
		"Administrators",
	}

	for _, privileged := range privilegedGroups {
		if strings.Contains(strings.ToLower(groupName), strings.ToLower(privileged)) {
			return true
		}
	}
	return false
}

func hasPrivilegedRoles(assignments []azure.AppRoleAssignment) bool {
	privilegedRoles := []string{
		"Global Administrator",
		"Privileged Role Administrator",
		"Security Administrator",
		"User Administrator",
		"Directory.ReadWrite.All",
		"RoleManagement.ReadWrite.Directory",
		"Application.ReadWrite.All",
	}

	for _, assignment := range assignments {
		// Use available fields from AppRoleAssignment
		assignmentName := assignment.PrincipalDisplayName
		resourceName := assignment.ResourceDisplayName

		for _, privileged := range privilegedRoles {
			if strings.Contains(strings.ToLower(assignmentName), strings.ToLower(privileged)) ||
				strings.Contains(strings.ToLower(resourceName), strings.ToLower(privileged)) {
				return true
			}
		}
	}
	return false
}

func extractDomainFromUPN(upn string) string {
	parts := strings.Split(upn, "@")
	if len(parts) == 2 {
		return strings.ToUpper(parts[1])
	}
	return "UNKNOWN"
}

func extractDomainFromGroup(group azure.Group) string {
	// Since OnPremisesDomainName doesn't exist, use a default
	// In a real implementation, you might extract this from other group properties
	return "AZUREAD"
}

func extractTypeFromOData(odataType string) string {
	if strings.Contains(odataType, "user") {
		return "User"
	} else if strings.Contains(odataType, "group") {
		return "Group"
	} else if strings.Contains(odataType, "servicePrincipal") {
		return "ServicePrincipal"
	} else if strings.Contains(odataType, "application") {
		return "Application"
	}
	return "Unknown"
}
