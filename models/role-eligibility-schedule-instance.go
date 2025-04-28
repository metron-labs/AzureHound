package models

type RoleEligibilityScheduleInstance struct {
	Id               string `json:"id,omitempty"`
	RoleDefinitionId string `json:"roleDefinitionId,omitempty"`
	PrincipalId      string `json:"principalId,omitempty"`
	DirectoryScopeId string `json:"directoryScopeId,omitempty"`
	StartDateTime    string `json:"startDateTime,omitempty"`
	TenantId         string `json:"tenantId,omitempty"`
}
