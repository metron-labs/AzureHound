package azure

type RoleManagementPolicyAssignment struct {
	Entity

	RoleDefinitionId                                  string   `json:"roleDefinitionId,omitempty"`
	EndUserAssignmentRequiresApproval                 bool     `json:"endUserAssignmentRequiresApproval,omitempty"`
	EndUserAssignmentRequiresCAPAuthenticationContext bool     `json:"endUserAssignmentRequiresCAPAuthenticationContext,omitempty"`
	EndUserAssignmentUserApprovers                    []string `json:"endUserAssignmentUserApprovers,omitempty"`
	EndUserAssignmentGroupApprovers                   []string `json:"endUserAssignmentGroupApprovers,omitempty"`
	EndUserAssignmentRequiresMFA                      bool     `json:"endUserAssignmentRequiresMFA,omitempty"`
	EndUserAssignmentRequiresJustification            bool     `json:"endUserAssignmentRequiresJustification,omitempty"`
	EndUserAssignmentRequiresTicketInformation        bool     `json:"endUserAssignmentRequiresTicketInformation,omitempty"`
	TenantId                                          string   `json:"tenantId,omitempty"`
}
