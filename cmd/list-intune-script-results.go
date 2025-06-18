// File: cmd/list-intune-script-results.go
// Command to retrieve results from your existing deployed BloodHound script

package cmd

import (
	"context"
	"fmt"
	"encoding/json"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/bloodhoundad/azurehound/v2/client"
	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/enums"
	"github.com/bloodhoundad/azurehound/v2/models/intune"
	"github.com/bloodhoundad/azurehound/v2/panicrecovery"
	"github.com/spf13/cobra"
)

var (
	scriptNameFilter string
	hoursBack        int
)

func init() {
	listRootCmd.AddCommand(listExistingScriptResultsCmd)
	
	listExistingScriptResultsCmd.Flags().StringVar(&scriptNameFilter, "script-name", "BHE_Script_Registry_Data_Collection", "Filter by script name")
	listExistingScriptResultsCmd.Flags().IntVar(&hoursBack, "hours-back", 24, "How many hours back to look for results")
}

var listExistingScriptResultsCmd = &cobra.Command{
	Use:   "intune-existing-results",
	Short: "Retrieve results from existing BloodHound Intune scripts",
	Long: `Retrieve and parse results from your existing deployed BloodHound registry collection script.

Examples:
  # Get results from the last 24 hours
  azurehound list intune-existing-results --jwt $JWT

  # Get results from last 48 hours
  azurehound list intune-existing-results --hours-back 48 --jwt $JWT

  # Filter by specific script name
  azurehound list intune-existing-results --script-name "BHE_Script_Registry_Data_Collection" --jwt $JWT`,
	Run:          listExistingScriptResultsCmdImpl,
	SilenceUsage: true,
}

func listExistingScriptResultsCmdImpl(cmd *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, os.Kill)
	defer gracefulShutdown(stop)

	log.V(1).Info("testing connections")
	azClient := connectAndCreateClient()
	log.Info("retrieving existing bloodhound script results...", "scriptName", scriptNameFilter, "hoursBack", hoursBack)
	start := time.Now()
	stream := retrieveExistingScriptResults(ctx, azClient)
	panicrecovery.HandleBubbledPanic(ctx, stop, log)
	outputStream(ctx, stream)
	duration := time.Since(start)
	log.Info("collection completed", "duration", duration.String())
}

func retrieveExistingScriptResults(ctx context.Context, client client.AzureClient) <-chan interface{} {
	out := make(chan interface{})

	go func() {
		defer panicrecovery.PanicRecovery()
		defer close(out)

		// Step 1: Find your existing BloodHound script
		scriptId := findBloodHoundScript(ctx, client)
		if scriptId == "" {
			log.Error(fmt.Errorf("script not found"), "unable to find bloodhound script", "scriptName", scriptNameFilter)
			return
		}

		log.Info("found bloodhound script", "scriptId", scriptId)

		// Step 2: Get recent results from that script
		collectExistingResults(ctx, client, scriptId, out)
	}()

	return out
}

func findBloodHoundScript(ctx context.Context, client client.AzureClient) string {
	params := query.GraphParams{}
	
	for script := range client.ListIntuneDeviceManagementScripts(ctx, params) {
		if script.Error != nil {
			log.Error(script.Error, "unable to list scripts")
			continue
		}

		// Look for your BloodHound script by name
		if strings.Contains(strings.ToLower(script.Ok.DisplayName), strings.ToLower(scriptNameFilter)) ||
		   strings.Contains(strings.ToLower(script.Ok.FileName), strings.ToLower(scriptNameFilter)) {
			log.V(1).Info("found matching script", 
				"displayName", script.Ok.DisplayName,
				"fileName", script.Ok.FileName,
				"id", script.Ok.Id)
			return script.Ok.Id
		}
	}

	return ""
}

func collectExistingResults(ctx context.Context, client client.AzureClient, scriptId string, out chan<- interface{}) {
	params := query.GraphParams{}
	
	// Calculate time threshold for recent results
	timeThreshold := time.Now().Add(-time.Duration(hoursBack) * time.Hour)
	
	resultCount := 0
	successCount := 0
	
	for result := range client.GetIntuneScriptResults(ctx, scriptId, params) {
		if result.Error != nil {
			log.Error(result.Error, "unable to get script results", "scriptId", scriptId)
			continue
		}

		resultCount++

		// Filter by time if we have timestamp info
		if result.Ok.LastStateUpdateDateTime.Before(timeThreshold) {
			log.V(2).Info("skipping old result", 
				"device", result.Ok.DeviceName,
				"timestamp", result.Ok.LastStateUpdateDateTime)
			continue
		}

		log.V(1).Info("processing script result", 
			"device", result.Ok.DeviceName,
			"state", result.Ok.RunState,
			"timestamp", result.Ok.LastStateUpdateDateTime)

		if result.Ok.RunState == "success" && result.Ok.ScriptOutput != "" {
			// Parse the actual BloodHound registry data from your script
			registryData := parseBloodHoundScriptOutput(result.Ok.ScriptOutput, result.Ok.DeviceName)
			if registryData != nil {
				successCount++
				select {
				case out <- NewAzureWrapper(enums.KindAZIntuneRegistryData, *registryData):
				case <-ctx.Done():
					return
				}
			}
		} else {
			// Still output the result info even if it failed
			select {
			case out <- NewAzureWrapper(enums.KindAZIntuneScriptResult, result.Ok):
			case <-ctx.Done():
				return
			}
		}
	}
	
	log.Info("finished processing script results", 
		"scriptId", scriptId,
		"totalResults", resultCount,
		"successfulParses", successCount)
}

func parseBloodHoundScriptOutput(scriptOutput string, deviceName string) *intune.RegistryCollectionResult {
	// Your script outputs JSON, so parse it directly
	var rawResult map[string]interface{}
	
	if err := json.Unmarshal([]byte(scriptOutput), &rawResult); err != nil {
		log.Error(err, "failed to parse script JSON output", "device", deviceName)
		return nil
	}

	// Convert the parsed JSON to our Go struct
	registryResult := &intune.RegistryCollectionResult{}
	
	// Parse DeviceInfo
	if deviceInfo, ok := rawResult["DeviceInfo"].(map[string]interface{}); ok {
		registryResult.DeviceInfo = intune.DeviceInfo{
			ComputerName:  getString(deviceInfo, "ComputerName"),
			Domain:        getString(deviceInfo, "Domain"),
			User:          getString(deviceInfo, "User"),
			Timestamp:     getString(deviceInfo, "Timestamp"),
			ScriptVersion: getString(deviceInfo, "ScriptVersion"),
		}
	}

	// Parse RegistryData array
	if registryData, ok := rawResult["RegistryData"].([]interface{}); ok {
		for _, item := range registryData {
			if regItem, ok := item.(map[string]interface{}); ok {
				regData := intune.RegistryKeyData{
					Path:       getString(regItem, "Path"),
					Purpose:    getString(regItem, "Purpose"),
					Accessible: getBool(regItem, "Accessible"),
					Error:      getString(regItem, "Error"),
				}
				
				// Parse Values map
				if values, ok := regItem["Values"].(map[string]interface{}); ok {
					regData.Values = values
				}
				
				registryResult.RegistryData = append(registryResult.RegistryData, regData)
			}
		}
	}

	// Parse SecurityIndicators
	if secIndicators, ok := rawResult["SecurityIndicators"].(map[string]interface{}); ok {
		registryResult.SecurityIndicators = intune.SecurityIndicators{
			UACDisabled:            getBool(secIndicators, "UACDisabled"),
			AutoAdminLogon:         getBool(secIndicators, "AutoAdminLogon"),
			WeakServicePermissions: getBool(secIndicators, "WeakServicePermissions"),
		}
		
		// Parse SuspiciousStartupItems array
		if suspiciousItems, ok := secIndicators["SuspiciousStartupItems"].([]interface{}); ok {
			for _, item := range suspiciousItems {
				if str, ok := item.(string); ok {
					registryResult.SecurityIndicators.SuspiciousStartupItems = append(
						registryResult.SecurityIndicators.SuspiciousStartupItems, str)
				}
			}
		}
	}

	// Parse Summary
	if summary, ok := rawResult["Summary"].(map[string]interface{}); ok {
		registryResult.Summary = intune.CollectionSummary{
			TotalKeysChecked: getInt(summary, "TotalKeysChecked"),
			AccessibleKeys:   getInt(summary, "AccessibleKeys"),
		}
		
		// Parse HighRiskIndicators array
		if riskIndicators, ok := summary["HighRiskIndicators"].([]interface{}); ok {
			for _, item := range riskIndicators {
				if str, ok := item.(string); ok {
					registryResult.Summary.HighRiskIndicators = append(
						registryResult.Summary.HighRiskIndicators, str)
				}
			}
		}
	}

	log.V(2).Info("successfully parsed script output", 
		"device", deviceName,
		"registryKeys", len(registryResult.RegistryData),
		"riskIndicators", len(registryResult.Summary.HighRiskIndicators))

	return registryResult
}

// Helper functions for safe type conversion
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func getInt(m map[string]interface{}, key string) int {
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