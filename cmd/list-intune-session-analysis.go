// cmd/list-intune-session-analysis.go - Simple working version without test command
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/bloodhoundad/azurehound/v2/client"
	"github.com/bloodhoundad/azurehound/v2/models/azure"
	"github.com/spf13/cobra"
)

func init() {
	listRootCmd.AddCommand(listIntuneSessionAnalysisCmd)

	// Add command flags
	listIntuneSessionAnalysisCmd.Flags().Duration("time-window", 24*time.Hour, "Time window for session analysis")
	listIntuneSessionAnalysisCmd.Flags().String("output-format", "console", "Output format (console, json)")
	listIntuneSessionAnalysisCmd.Flags().String("export-bloodhound", "", "Export BloodHound data to file")
	listIntuneSessionAnalysisCmd.Flags().Bool("verbose", false, "Enable verbose output")
	listIntuneSessionAnalysisCmd.Flags().Bool("admin-only", false, "Show only devices with admin sessions")
	listIntuneSessionAnalysisCmd.Flags().Int("days-back", 7, "Number of days back to collect sign-in logs")
	listIntuneSessionAnalysisCmd.Flags().Int("max-results", 1000, "Maximum number of sign-in events to collect")
}

var listIntuneSessionAnalysisCmd = &cobra.Command{
	Use:          "intune-session-analysis",
	Short:        "Analyze session security using Microsoft Graph Sign-In APIs",
	Long:         "Performs comprehensive session security analysis using Microsoft Graph Sign-In APIs for BloodHound integration",
	Run:          listIntuneSessionAnalysisCmdImpl,
	SilenceUsage: true,
}

func listIntuneSessionAnalysisCmdImpl(cmd *cobra.Command, args []string) {
	ctx, stop := context.WithCancel(cmd.Context())
	defer stop()

	// Connect to Azure
	azClient := connectAndCreateClient()

	// Get command line options
	verbose, _ := cmd.Flags().GetBool("verbose")
	adminOnly, _ := cmd.Flags().GetBool("admin-only")
	exportBloodhound, _ := cmd.Flags().GetString("export-bloodhound")

	if verbose {
		fmt.Printf("🔍 Starting session analysis using Microsoft Graph Sign-In Logs API\n")
		fmt.Printf("🎯 Admin sessions only: %v\n", adminOnly)
	}

	// Perform session analysis
	analysisResults, err := performSessionAnalysis(ctx, azClient, adminOnly, verbose)
	if err != nil {
		fmt.Printf("❌ Session analysis failed: %v\n", err)
		os.Exit(1)
	}

	// Display results
	displaySimpleSessionResults(analysisResults, exportBloodhound, verbose)
}

func performSessionAnalysis(ctx context.Context, azClient client.AzureClient, adminOnly bool, verbose bool) ([]azure.DeviceSessionAnalysis, error) {
	if verbose {
		fmt.Printf("🚀 Collecting session data from Microsoft Graph Sign-In Logs API...\n")
	}

	// Use the CollectSessionDataDirectly method
	sessionDataChannel := azClient.CollectSessionDataDirectly(ctx)

	var results []azure.DeviceSessionAnalysis
	successCount := 0
	errorCount := 0

	// Process session data
	for sessionResult := range sessionDataChannel {
		if sessionResult.Error != nil {
			if verbose {
				fmt.Printf("⚠️  Session collection error: %v\n", sessionResult.Error)
			}
			errorCount++
			continue
		}

		// Filter for admin sessions if requested
		if adminOnly && !hasAdminSessions(sessionResult.Ok.SessionData) {
			continue
		}

		// Create simple analysis
		analysis := createSimpleAnalysis(sessionResult.Ok)
		results = append(results, analysis)
		successCount++

		if verbose && successCount%5 == 0 {
			fmt.Printf("✅ Analyzed %d devices, %d errors so far\n", successCount, errorCount)
		}
	}

	if verbose {
		fmt.Printf("📊 Analysis completed: %d successful, %d errors\n", successCount, errorCount)
	}

	if successCount == 0 {
		return nil, fmt.Errorf("no devices were successfully analyzed - check Graph API permissions and sign-in log availability")
	}

	return results, nil
}

func createSimpleAnalysis(deviceData azure.DeviceSessionData) azure.DeviceSessionAnalysis {
	analysis := azure.DeviceSessionAnalysis{
		Device:            deviceData.Device,
		AnalysisTimestamp: deviceData.CollectedAt,
		SessionFindings:   []azure.SessionSecurityFinding{},
		RiskScore:         0,
		SecurityPosture:   "Secure",
		LastUpdated:       time.Now(),
	}

	// Simple risk analysis
	adminSessions := deviceData.SessionData.Summary.AdminSessions
	totalSessions := deviceData.SessionData.Summary.TotalActiveSessions

	// Calculate risk score
	riskScore := 0
	if adminSessions > 0 {
		riskScore += adminSessions * 20
	}
	if totalSessions > 5 {
		riskScore += 10
	}
	if len(deviceData.SessionData.SecurityIndicators.SuspiciousActivities) > 0 {
		riskScore += 30
	}

	analysis.RiskScore = riskScore

	// Set security posture
	switch {
	case riskScore >= 60:
		analysis.SecurityPosture = "High_Risk"
	case riskScore >= 30:
		analysis.SecurityPosture = "Moderate"
	case riskScore >= 10:
		analysis.SecurityPosture = "Low_Risk"
	default:
		analysis.SecurityPosture = "Secure"
	}

	// Add simple findings
	if adminSessions > 0 {
		finding := azure.SessionSecurityFinding{
			ID:          fmt.Sprintf("ADMIN_SESSIONS_%s", deviceData.Device.ID),
			Title:       "Administrator Sessions Detected",
			Severity:    "MEDIUM",
			Category:    "Privilege Management",
			Description: fmt.Sprintf("Found %d administrator sessions", adminSessions),
			Evidence:    []string{fmt.Sprintf("Admin sessions: %d", adminSessions)},
		}
		analysis.SessionFindings = append(analysis.SessionFindings, finding)
	}

	return analysis
}

func hasAdminSessions(sessionData azure.SessionData) bool {
	return sessionData.Summary.AdminSessions > 0
}

func displaySimpleSessionResults(results []azure.DeviceSessionAnalysis, exportPath string, verbose bool) {
	fmt.Printf("\n🔍 MICROSOFT GRAPH SESSION ANALYSIS RESULTS\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n")
	fmt.Printf("📊 Data Source: Microsoft Graph Sign-In Logs API\n")
	fmt.Printf("📅 Analysis Time: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	if len(results) == 0 {
		fmt.Printf("❌ No session data retrieved from Microsoft Graph API\n")
		return
	}

	// Calculate summary
	totalDevices := len(results)
	highRiskDevices := 0
	totalFindings := 0

	for _, result := range results {
		if result.SecurityPosture == "High_Risk" {
			highRiskDevices++
		}
		totalFindings += len(result.SessionFindings)
	}

	// Display summary
	fmt.Printf("📊 SUMMARY:\n")
	fmt.Printf("   🖥️  Total Devices: %d\n", totalDevices)
	fmt.Printf("   🔴 High Risk Devices: %d\n", highRiskDevices)
	fmt.Printf("   🚨 Total Findings: %d\n", totalFindings)
	fmt.Printf("\n")

	// Display devices
	fmt.Printf("📋 DEVICE DETAILS:\n")
	fmt.Printf("─────────────────────────────────────────────────────────\n")

	for i, result := range results {
		postureEmoji := getPostureEmoji(result.SecurityPosture)
		fmt.Printf("%s Device #%d: %s\n", postureEmoji, i+1, result.Device.DeviceName)
		fmt.Printf("   💻 OS: %s\n", result.Device.OperatingSystem)
		fmt.Printf("   👤 User: %s\n", getDisplayValue(result.Device.UserPrincipalName))
		fmt.Printf("   📊 Risk Score: %d/100\n", result.RiskScore)
		fmt.Printf("   🛡️  Security Posture: %s\n", result.SecurityPosture)

		if len(result.SessionFindings) > 0 {
			fmt.Printf("   🚨 Findings:\n")
			for _, finding := range result.SessionFindings {
				fmt.Printf("      • %s (%s)\n", finding.Title, finding.Severity)
			}
		}
		fmt.Printf("\n")
	}

	// Export if requested
	if exportPath != "" {
		if err := exportSessionData(results, exportPath); err != nil {
			fmt.Printf("❌ Failed to export data: %v\n", err)
		} else {
			fmt.Printf("✅ Session data exported to: %s\n", exportPath)
		}
	}

	// Display recommendations
	if highRiskDevices > 0 || totalFindings > 0 {
		fmt.Printf("💡 RECOMMENDATIONS:\n")
		fmt.Printf("─────────────────────────────────────────────────────────\n")
		fmt.Printf("   1. Review devices with high risk scores\n")
		fmt.Printf("   2. Investigate administrator session usage\n")
		fmt.Printf("   3. Implement Azure AD Privileged Identity Management\n")
		fmt.Printf("   4. Enable Conditional Access policies\n")
		fmt.Printf("   5. Monitor sign-in patterns regularly\n")
	} else {
		fmt.Printf("✅ No immediate security concerns detected.\n")
	}
}

func getPostureEmoji(posture string) string {
	switch posture {
	case "High_Risk":
		return "🔴"
	case "Moderate":
		return "🟡"
	case "Low_Risk":
		return "🟢"
	case "Secure":
		return "✅"
	default:
		return "❓"
	}
}

func exportSessionData(results []azure.DeviceSessionAnalysis, outputPath string) error {
	data := map[string]interface{}{
		"meta": map[string]interface{}{
			"type":         "azure_session_analysis",
			"version":      "1.0",
			"count":        len(results),
			"collected_at": time.Now().Format(time.RFC3339),
			"data_source":  "Microsoft Graph Sign-In Logs API",
		},
		"devices": results,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	return os.WriteFile(outputPath, jsonData, 0644)
}
