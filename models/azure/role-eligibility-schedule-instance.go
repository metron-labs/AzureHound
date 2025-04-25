package azure

type RoleEligibilityScheduleInstance struct {
	Entity

	RoleDefinitionId string `json:"roleDefinitionId,omitempty"`

	PrincipalId string `json:"principalId,omitempty"`

	DirectoryScopeId string `json:"directoryScopeId,omitempty"`

	StartDateTime string `json:"startDateTime,omitempty"`

	TenantId string `json:"tenantId,omitempty"`
}
