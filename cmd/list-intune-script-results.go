// File: cmd/list-intune-script-results.go
// Command to collect existing BloodHound script results from Intune

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/bloodhoundad/azurehound/v2/client"
	clientconfig "github.com/bloodhoundad/azurehound/v2/client/config"
	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/config"
	"github.com/bloodhoundad/azurehound/v2/models/intune"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func init() {
	listRootCmd.AddCommand(listIntuneExistingResultsCmd)
}

var listIntuneExistingResultsCmd = &cobra.Command{
	Use:          "intune-existing-results",
	Short:        "Collect existing BloodHound script results from Intune",
	Long:         `This command retrieves results from previously executed BloodHound PowerShell scripts deployed to Intune managed devices. It looks for registry collection data and other security-relevant information gathered by the scripts.`,
	Run:          listIntuneExistingResultsCmdImpl,
	SilenceUsage: true,
}

func listIntuneExistingResultsCmdImpl(cmd *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, os.Kill)
	defer gracefulShutdown(stop)

	log := zerolog.Ctx(ctx)

	// Load configuration values using the correct signature
	config.LoadValues(cmd, config.Options())
	
	// Create client config - this might need to be populated from the global config
	clientConf := clientconfig.Config{
		// We'll use default values for now, but this should be populated
		// from the loaded configuration in a real implementation
	}

	azClient, err := client.NewClient(clientConf)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create client")
		return
	}
	defer azClient.CloseIdleConnections()

	log.Info().Str("scriptName", "BHE_Script_Registry_Data_Collection").
		Int("hoursBack", 24).
		Msg("retrieving existing bloodhound script results...")

	// Step 1: Find the BloodHound registry script
	script, err := findBloodHoundRegistryScript(ctx, azClient)
	if err != nil {
		log.Error().Err(err).Msg("unable to find bloodhound script")
		
		// Try to list all scripts to help with debugging
		log.Info().Msg("listing all available scripts for debugging...")
		scriptsChan := azClient.ListIntuneDeviceManagementScripts(ctx, query.GraphParams{Top: 100})
		
		scriptCount := 0
		for result := range scriptsChan {
			if result.Error != nil {
				log.Error().Err(result.Error).Msg("error listing scripts")
				break
			}
			scriptCount++
			log.Info().
				Str("script_id", result.Ok.Id).
				Str("display_name", result.Ok.DisplayName).
				Str("created_date", result.Ok.CreatedDateTime.Format(time.RFC3339)).
				Msg("found script")
		}
		
		if scriptCount == 0 {
			log.Error().Msg("no scripts found - ensure PowerShell scripts are deployed to Intune")
		} else {
			log.Info().Int("total_scripts", scriptCount).Msg("scripts found but none match BloodHound registry pattern")
		}
		return
	}

	log.Info().
		Str("script_id", script.Id).
		Str("display_name", script.DisplayName).
		Str("created_date", script.CreatedDateTime.Format(time.RFC3339)).
		Msg("found bloodhound registry script")

	// Step 2: Get script results and parse them
	params := query.GraphParams{Top: 1000}
	resultsChan := azClient.GetIntuneScriptResults(ctx, script.Id, params)
	
	var allResults []interface{}
	deviceCount := 0
	errorCount := 0

	// Create output directory
	outputDir := fmt.Sprintf("bloodhound-intune-results-%s", time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Error().Err(err).Str("directory", outputDir).Msg("failed to create output directory")
		return
	}

	log.Info().Str("output_directory", outputDir).Msg("saving results to directory")

	for result := range resultsChan {
		if result.Error != nil {
			errorCount++
			log.Error().Err(result.Error).Msg("error processing script result")
			continue
		}

		scriptResult := result.Ok
		
		// Parse the registry data from the script output
		if registryData, err := parseRegistryDataFromScriptOutput(scriptResult.ResultMessage); err != nil {
			log.Error().Err(err).Str("device_id", scriptResult.DeviceId).Msg("failed to parse registry data")
			errorCount++
			continue
		} else {
			deviceCount++
			
			log.Info().
				Str("computer_name", registryData.DeviceInfo.ComputerName).
				Str("domain", registryData.DeviceInfo.Domain).
				Str("timestamp", registryData.DeviceInfo.Timestamp).
				Int("registry_keys", len(registryData.RegistryData)).
				Bool("uac_disabled", registryData.SecurityIndicators.UACDisabled).
				Bool("auto_admin_logon", registryData.SecurityIndicators.AutoAdminLogon).
				Msg("collected registry data from device")

			// Save individual device data
			deviceFileName := fmt.Sprintf("device-%s-registry.json", registryData.DeviceInfo.ComputerName)
			deviceFilePath := filepath.Join(outputDir, deviceFileName)
			
			if deviceJSON, err := json.MarshalIndent(registryData, "", "  "); err != nil {
				log.Error().Err(err).Str("device", registryData.DeviceInfo.ComputerName).Msg("failed to marshal device data")
			} else {
				if err := os.WriteFile(deviceFilePath, deviceJSON, 0644); err != nil {
					log.Error().Err(err).Str("file", deviceFilePath).Msg("failed to write device file")
				} else {
					log.Info().Str("file", deviceFileName).Msg("saved device registry data")
				}
			}

			// Add to aggregate results
			allResults = append(allResults, registryData)

			// Log security findings
			if registryData.SecurityIndicators.UACDisabled {
				log.Warn().Str("device", registryData.DeviceInfo.ComputerName).Msg("UAC is disabled on device")
			}
			if registryData.SecurityIndicators.AutoAdminLogon {
				log.Warn().Str("device", registryData.DeviceInfo.ComputerName).Msg("Auto admin logon enabled on device")
			}

			// Check for interesting registry values
			for _, regEntry := range registryData.RegistryData {
				if regEntry.Path == "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" && len(regEntry.Values) > 0 {
					log.Info().
						Str("device", registryData.DeviceInfo.ComputerName).
						Int("startup_items", len(regEntry.Values)).
						Msg("found startup items in registry")
				}
			}
		}
	}

	// Save aggregate results
	summaryData := map[string]interface{}{
		"collection_timestamp": time.Now().Format(time.RFC3339),
		"script_info": map[string]interface{}{
			"id":           script.Id,
			"name":         script.DisplayName,
			"created_date": script.CreatedDateTime.Format(time.RFC3339),
		},
		"summary": map[string]interface{}{
			"total_devices":       deviceCount,
			"errors":             errorCount,
			"devices_with_issues": 0, // Could be calculated
		},
		"results": allResults,
	}

	summaryPath := filepath.Join(outputDir, "summary.json")
	if summaryJSON, err := json.MarshalIndent(summaryData, "", "  "); err != nil {
		log.Error().Err(err).Msg("failed to marshal summary data")
	} else {
		if err := os.WriteFile(summaryPath, summaryJSON, 0644); err != nil {
			log.Error().Err(err).Str("file", summaryPath).Msg("failed to write summary file")
		} else {
			log.Info().Str("file", "summary.json").Msg("saved summary data")
		}
	}

	// Final status
	if deviceCount == 0 && errorCount == 0 {
		log.Warn().Msg("no script execution results found - ensure the script has been run on devices")
	} else {
		log.Info().
			Int("devices_processed", deviceCount).
			Int("errors", errorCount).
			Str("output_directory", outputDir).
			Msg("collection completed")
	}
}

// findBloodHoundRegistryScript - Find the BloodHound registry collection script
func findBloodHoundRegistryScript(ctx context.Context, azClient client.AzureClient) (*intune.DeviceManagementScript, error) {
	// Look for scripts with registry-related names
	searchTerms := []string{"Registry", "BloodHound", "BHE_Script", "registry"}
	
	for _, term := range searchTerms {
		params := query.GraphParams{
			Filter: fmt.Sprintf("contains(displayName,'%s')", term),
			Top:    50,
		}

		scriptChan := azClient.ListIntuneDeviceManagementScripts(ctx, params)
		
		for result := range scriptChan {
			if result.Error != nil {
				continue
			}
			
			script := result.Ok
			// Check if this looks like our registry collection script
			if strings.Contains(strings.ToLower(script.DisplayName), "registry") ||
			   strings.Contains(strings.ToLower(script.DisplayName), "bloodhound") {
				return &script, nil
			}
		}
	}
	
	return nil, fmt.Errorf("BloodHound registry script not found")
}

// parseRegistryDataFromScriptOutput - Parse JSON data from PowerShell script output
func parseRegistryDataFromScriptOutput(output string) (*intune.RegistryCollectionResult, error) {
	// Look for the JSON data between REGISTRY_DATA_START and REGISTRY_DATA_END markers
	startMarker := "REGISTRY_DATA_START"
	endMarker := "REGISTRY_DATA_END"
	
	startIdx := strings.Index(output, startMarker)
	endIdx := strings.Index(output, endMarker)
	
	if startIdx == -1 || endIdx == -1 {
		return nil, fmt.Errorf("registry data markers not found in script output")
	}
	
	// Extract JSON data
	jsonStart := startIdx + len(startMarker)
	jsonData := strings.TrimSpace(output[jsonStart:endIdx])
	
	// Parse the JSON
	var rawData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}
	
	// Convert to our structured format
	result := &intune.RegistryCollectionResult{}
	
	// Parse device info
	if deviceInfo, ok := rawData["DeviceInfo"].(map[string]interface{}); ok {
		result.DeviceInfo = intune.DeviceInfo{
			ComputerName:  getStringValue(deviceInfo, "ComputerName"),
			Domain:        getStringValue(deviceInfo, "Domain"),
			User:          getStringValue(deviceInfo, "User"),
			Timestamp:     getStringValue(deviceInfo, "Timestamp"),
			ScriptVersion: getStringValue(deviceInfo, "ScriptVersion"),
		}
	}
	
	// Parse registry data
	if registryDataArray, ok := rawData["RegistryData"].([]interface{}); ok {
		result.RegistryData = make([]intune.RegistryKeyData, len(registryDataArray))
		
		for i, item := range registryDataArray {
			if regItem, ok := item.(map[string]interface{}); ok {
				result.RegistryData[i] = intune.RegistryKeyData{
					Path:       getStringValue(regItem, "Path"),
					Purpose:    getStringValue(regItem, "Purpose"),
					Values:     getMapValue(regItem, "Values"),
					Accessible: getBoolValue(regItem, "Accessible"),
					Error:      getStringValue(regItem, "Error"),
				}
			}
		}
	}
	
	// Parse security indicators
	if indicators, ok := rawData["SecurityIndicators"].(map[string]interface{}); ok {
		result.SecurityIndicators = intune.SecurityIndicators{
			UACDisabled:    getBoolValue(indicators, "UACDisabled"),
			AutoAdminLogon: getBoolValue(indicators, "AutoAdminLogon"),
		}
	}
	
	// Parse summary
	if summary, ok := rawData["Summary"].(map[string]interface{}); ok {
		result.Summary = intune.CollectionSummary{
			TotalKeysChecked: getIntValue(summary, "TotalKeysChecked"),
			AccessibleKeys:   getIntValue(summary, "AccessibleKeys"),
		}
	}
	
	return result, nil
}

// Helper functions for type conversion
func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolValue(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func getIntValue(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		if f, ok := val.(float64); ok {
			return int(f)
		}
		if i, ok := val.(int); ok {
			return i
		}
	}
	return 0
}

func getMapValue(m map[string]interface{}, key string) map[string]interface{} {
	if val, ok := m[key]; ok {
		if mapVal, ok := val.(map[string]interface{}); ok {
			return mapVal
		}
	}
	return make(map[string]interface{})
}