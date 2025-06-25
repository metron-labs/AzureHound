// cmd/list-intune-registry-analysis.go
package cmd

import (
	"context"
	"fmt"

	"github.com/bloodhoundad/azurehound/v2/client"
	"github.com/bloodhoundad/azurehound/v2/models/azure"
	"github.com/spf13/cobra"
)

func init() {
	listRootCmd.AddCommand(listIntuneRegistryAnalysisCmd)
}

var listIntuneRegistryAnalysisCmd = &cobra.Command{
	Use:          "intune-registry-analysis",
	Long:         "Performs security analysis on collected registry data and formats for BloodHound",
	Run:          listIntuneRegistryAnalysisCmdImpl,
	SilenceUsage: true,
}

func listIntuneRegistryAnalysisCmdImpl(cmd *cobra.Command, args []string) {
	ctx, stop := context.WithCancel(cmd.Context())
	defer stop()

	azClient := connectAndCreateClient()

	if analysisResults, err := performRegistrySecurityAnalysis(ctx, azClient); err != nil {
		exit(err)
	} else {
		// Simple output - print analysis results
		fmt.Printf("Analyzed %d devices for security issues\n", len(analysisResults))

		for _, analysis := range analysisResults {
			fmt.Printf("Device: %s - Risk Score: %d - Compliance: %s\n",
				analysis.Device.DeviceName,
				analysis.RiskScore,
				analysis.ComplianceStatus)

			if len(analysis.SecurityFindings) > 0 {
				fmt.Printf("  Security Findings: %d\n", len(analysis.SecurityFindings))
				for _, finding := range analysis.SecurityFindings {
					fmt.Printf("    - %s (%s)\n", finding.Title, finding.Severity)
				}
			}
		}
	}
}

func performRegistrySecurityAnalysis(ctx context.Context, azClient client.AzureClient) ([]azure.DeviceSecurityAnalysis, error) {
	var (
		out    = make([]azure.DeviceSecurityAnalysis, 0)
		count  = 0
		errors = 0
	)

	// Get registry data from all devices
	registryDataResults := azClient.CollectRegistryDataFromAllDevices(ctx)

	for result := range registryDataResults {
		if result.Error != nil {
			errors++
			continue
		}

		// Perform basic security analysis on the collected data
		analysis := performBasicDeviceSecurityAnalysis(result.Ok)
		out = append(out, analysis)
		count++
	}

	return out, nil
}

func performBasicDeviceSecurityAnalysis(deviceData azure.DeviceRegistryData) azure.DeviceSecurityAnalysis {
	analysis := azure.DeviceSecurityAnalysis{
		Device:            deviceData.Device,
		AnalysisTimestamp: deviceData.CollectedAt,
		SecurityFindings:  []azure.SecurityFinding{},
		EscalationVectors: []azure.EscalationVector{},
		RiskScore:         0,
		ComplianceStatus:  "COMPLIANT",
	}

	// Simple analysis based on the collected registry data
	if deviceData.RegistryData.SecurityIndicators.UACDisabled {
		finding := azure.SecurityFinding{
			ID:              "UAC_DISABLED",
			Title:           "User Account Control Disabled",
			Severity:        "HIGH",
			Category:        "Privilege Escalation",
			Description:     "UAC is disabled, allowing privilege escalation",
			Evidence:        []string{"UAC is disabled in registry"},
			Recommendations: []string{"Enable UAC"},
			MITREAttack:     []string{"T1548.002"},
		}
		analysis.SecurityFindings = append(analysis.SecurityFindings, finding)
		analysis.RiskScore += 25
	}

	if deviceData.RegistryData.SecurityIndicators.AutoAdminLogon {
		finding := azure.SecurityFinding{
			ID:              "AUTO_ADMIN_LOGON",
			Title:           "Automatic Administrator Logon Enabled",
			Severity:        "CRITICAL",
			Category:        "Credential Exposure",
			Description:     "Automatic administrator logon is enabled",
			Evidence:        []string{"AutoAdminLogon is enabled in registry"},
			Recommendations: []string{"Disable automatic administrator logon"},
			MITREAttack:     []string{"T1552.002"},
		}
		analysis.SecurityFindings = append(analysis.SecurityFindings, finding)
		analysis.RiskScore += 40
	}

	// Set compliance status based on risk score
	if analysis.RiskScore >= 50 {
		analysis.ComplianceStatus = "NON_COMPLIANT"
	} else if analysis.RiskScore >= 25 {
		analysis.ComplianceStatus = "PARTIALLY_COMPLIANT"
	}

	return analysis
}
