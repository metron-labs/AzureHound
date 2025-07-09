// Updated implementation for client/user_roles.go

package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/models/azure"
)

// MemberOfObject represents objects returned by memberOf API
type MemberOfObject struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	ODataType   string `json:"@odata.type"`
}

// GetUserMemberOf gets all groups and roles a user belongs to
func (s *azureClient) GetUserMemberOf(ctx context.Context, userPrincipalName string) ([]azure.DirectoryObject, error) {
	path := fmt.Sprintf("/beta/users/%s/memberOf", userPrincipalName)

	params := query.GraphParams{
		Select: []string{"id", "displayName", "@odata.type"},
	}

	resultChan := make(chan AzureResult[MemberOfObject])
	go getAzureObjectList[MemberOfObject](s.msgraph, ctx, path, params, resultChan)

	var objects []azure.DirectoryObject
	for result := range resultChan {
		if result.Error != nil {
			return nil, result.Error
		}

		// Convert to our model
		obj := azure.DirectoryObject{
			ID:          result.Ok.ID,
			DisplayName: result.Ok.DisplayName,
			ObjectType:  result.Ok.ODataType,
		}
		objects = append(objects, obj)
	}

	return objects, nil
}

// Enhanced role detection using memberOf API
func (s *azureClient) isAdminUserEnhanced(ctx context.Context, userPrincipalName string) bool {
	memberOf, err := s.GetUserMemberOf(ctx, userPrincipalName)
	if err != nil {
		// Fall back to heuristic if API fails
		return isAdminUserHeuristic(userPrincipalName)
	}

	// Define admin role names and admin group patterns
	adminRoleNames := map[string]bool{
		"global administrator":                    true,
		"privileged role administrator":           true,
		"security administrator":                  true,
		"user administrator":                      true,
		"helpdesk administrator":                  true,
		"exchange administrator":                  true,
		"sharepoint administrator":                true,
		"teams administrator":                     true,
		"intune administrator":                    true,
		"cloud application administrator":         true,
		"application administrator":               true,
		"authentication administrator":            true,
		"privileged authentication administrator": true,
		"directory readers":                       true,
		"directory writers":                       true,
	}

	adminGroupPatterns := []string{
		"admin", "administrator", "domain admin", "enterprise admin",
		"schema admin", "global admin", "tenant admin", "it admin",
		"system admin", "security admin", "compliance admin",
	}

	for _, obj := range memberOf {
		displayName := strings.ToLower(obj.DisplayName)

		// Check if it's a directory role (admin role)
		if obj.ObjectType == "#microsoft.graph.directoryRole" {
			if adminRoleNames[displayName] {
				return true
			}
		}

		// Check if it's an admin group
		if obj.ObjectType == "#microsoft.graph.group" {
			for _, pattern := range adminGroupPatterns {
				if strings.Contains(displayName, pattern) {
					return true
				}
			}
		}
	}

	return false
}

func (s *azureClient) isServiceUserEnhanced(ctx context.Context, userPrincipalName string) bool {
	memberOf, err := s.GetUserMemberOf(ctx, userPrincipalName)
	if err != nil {
		// Fall back to heuristic if API fails
		return isServiceUserHeuristic(userPrincipalName)
	}

	// Service account group patterns
	serviceGroupPatterns := []string{
		"service", "svc", "application", "app", "automation",
		"system", "daemon", "bot", "sync", "backup", "monitoring",
		"service account", "application account", "system account",
	}

	for _, obj := range memberOf {
		if obj.ObjectType == "#microsoft.graph.group" {
			groupName := strings.ToLower(obj.DisplayName)
			for _, pattern := range serviceGroupPatterns {
				if strings.Contains(groupName, pattern) {
					return true
				}
			}
		}
	}

	// Also check the UPN itself for service patterns
	return isServiceUserHeuristic(userPrincipalName)
}

// Alternative: Get only directory roles (more specific for admin detection)
func (s *azureClient) GetUserDirectoryRoles(ctx context.Context, userPrincipalName string) ([]azure.DirectoryRole, error) {
	path := fmt.Sprintf("/beta/users/%s/memberOf", userPrincipalName)

	params := query.GraphParams{
		Filter: "$filter=@odata.type eq 'microsoft.graph.directoryRole'",
		Select: []string{"id", "displayName", "description"},
	}

	resultChan := make(chan AzureResult[azure.DirectoryRole])
	go getAzureObjectList[azure.DirectoryRole](s.msgraph, ctx, path, params, resultChan)

	var roles []azure.DirectoryRole
	for result := range resultChan {
		if result.Error != nil {
			return nil, result.Error
		}
		roles = append(roles, result.Ok)
	}

	return roles, nil
}

// For your intune_sessions_direct.go, you can now use this more accurate detection:
func (s *azureClient) analyzeUserPrivileges(ctx context.Context, userPrincipalName string) (isAdmin bool, isService bool, groups []string) {
	memberOf, err := s.GetUserMemberOf(ctx, userPrincipalName)
	if err != nil {
		// Fallback to heuristics
		return isAdminUserHeuristic(userPrincipalName), isServiceUserHeuristic(userPrincipalName), []string{}
	}

	var groupNames []string

	for _, obj := range memberOf {
		groupNames = append(groupNames, obj.DisplayName)

		displayName := strings.ToLower(obj.DisplayName)

		// Check for admin roles/groups
		if obj.ObjectType == "#microsoft.graph.directoryRole" {
			isAdmin = true // Any directory role is considered admin
		} else if obj.ObjectType == "#microsoft.graph.group" {
			// Check admin group patterns
			adminPatterns := []string{"admin", "administrator", "domain admin", "enterprise admin"}
			for _, pattern := range adminPatterns {
				if strings.Contains(displayName, pattern) {
					isAdmin = true
					break
				}
			}

			// Check service group patterns
			servicePatterns := []string{"service", "svc", "application", "app", "automation", "system"}
			for _, pattern := range servicePatterns {
				if strings.Contains(displayName, pattern) {
					isService = true
					break
				}
			}
		}
	}

	return isAdmin, isService, groupNames
}
