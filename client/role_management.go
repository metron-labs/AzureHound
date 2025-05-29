package client

//go:generate go run http://go.uber.org/mock/mockgen  -destination=./mocks/client.go -package=mocks . AzureRoleManagementClient

import (
	"context"
	"fmt"

	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/constants"
	"github.com/bloodhoundad/azurehound/v2/models/azure"
)

// AzureRoleManagementClient defines the methods to interface with the Azure role based access control (RBAC) API
type AzureRoleManagementClient interface {
	ListRoleAssignmentPolicies(ctx context.Context, params query.GraphParams) <-chan AzureResult[azure.UnifiedRoleManagementPolicyAssignment]
}

// ListRoleAssignmentPolicies makes a GET request to  https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments
// This endpoint requires the RoleManagement.Read.All permission
// https://learn.microsoft.com/en-us/graph/permissions-reference#rolemanagementreadall
// Endpoint documentation: https://learn.microsoft.com/en-us/graph/api/policyroot-list-rolemanagementpolicyassignments?view=graph-rest-1.0&tabs=http
func (s azureClient) ListRoleAssignmentPolicies(ctx context.Context, params query.GraphParams) <-chan AzureResult[azure.UnifiedRoleManagementPolicyAssignment] {
	var (
		out  = make(chan AzureResult[azure.UnifiedRoleManagementPolicyAssignment])
		path = fmt.Sprintf("/%s/policies/roleManagementPolicyAssignments", constants.GraphApiVersion)
	)

	go getAzureObjectList[azure.UnifiedRoleManagementPolicyAssignment](s.msgraph, ctx, path, params, out)

	return out
}
