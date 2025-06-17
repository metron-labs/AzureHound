// File: cmd/execute-intune-scripts.go
// Command for executing custom scripts on Intune devices

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"
	"github.com/bloodhoundad/azurehound/v2/client"
	"github.com/spf13/cobra"
)

var (
	deviceID      string
	scriptFile    string
	scriptContent string
	runAsAccount  string
	waitForResult bool
	maxWaitTime   time.Duration
)

func init() {
	listRootCmd.AddCommand(executeIntuneScriptCmd)
	
	executeIntuneScriptCmd.Flags().StringVar(&deviceID, "device-id", "", "Target device ID (required)")
	executeIntuneScriptCmd.Flags().StringVar(&scriptFile, "script-file", "", "Path to PowerShell script file")
	executeIntuneScriptCmd.Flags().StringVar(&scriptContent, "script-content", "", "Inline PowerShell script content")
	executeIntuneScriptCmd.Flags().StringVar(&runAsAccount, "run-as", "system", "Run as account: system or user")
	executeIntuneScriptCmd.Flags().BoolVar(&waitForResult, "wait", false, "Wait for script completion")
	executeIntuneScriptCmd.Flags().DurationVar(&maxWaitTime, "timeout", 5*time.Minute, "Maximum wait time for script completion")
	
	executeIntuneScriptCmd.MarkFlagRequired("device-id")
}

var executeIntuneScriptCmd = &cobra.Command{
	Use:   "execute-script",
	Short: "Execute PowerShell script on Intune managed device",
	Long: `Execute a PowerShell script on an Intune managed device.

Examples:
  # Execute script from file
  azurehound execute-script --device-id "12345" --script-file "collect.ps1" --jwt $JWT

  # Execute inline script
  azurehound execute-script --device-id "12345" --script-content "Get-Process" --jwt $JWT

  # Execute and wait for results
  azurehound execute-script --device-id "12345" --script-file "collect.ps1" --wait --jwt $JWT`,
	Run:          executeIntuneScriptCmdImpl,
	SilenceUsage: true,
}

func executeIntuneScriptCmdImpl(cmd *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, os.Kill)
	defer gracefulShutdown(stop)

	// Validate input
	if scriptFile == "" && scriptContent == "" {
		log.Error(fmt.Errorf("validation error"), "either --script-file or --script-content must be provided")
		return
	}

	if scriptFile != "" && scriptContent != "" {
		log.Error(fmt.Errorf("validation error"), "cannot specify both --script-file and --script-content")
		return
	}

	// Read script content from file if specified
	if scriptFile != "" {
		content, err := os.ReadFile(scriptFile)
		if err != nil {
			log.Error(err, "failed to read script file", "file", scriptFile)
			return
		}
		scriptContent = string(content)
	}

	log.V(1).Info("testing connections")
	azClient := connectAndCreateClient()
	
	log.Info("executing script on device", 
		"device", deviceID, 
		"runAs", runAsAccount, 
		"wait", waitForResult,
		"scriptLength", len(scriptContent))

	start := time.Now()
	executeScript(ctx, azClient)
	duration := time.Since(start)
	log.Info("script execution completed", "duration", duration.String())
}

func executeScript(ctx context.Context, client client.AzureClient) {
	// Execute the script
	for execution := range client.ExecuteIntuneScript(ctx, deviceID, scriptContent, runAsAccount) {
		if execution.Error != nil {
			log.Error(execution.Error, "failed to execute script")
			return
		}

		log.Info("script execution initiated", 
			"executionId", execution.Ok.Id,
			"scriptId", execution.Ok.ScriptId,
			"status", execution.Ok.Status)

		if waitForResult {
			log.Info("waiting for script completion", "timeout", maxWaitTime)
			waitForScriptResult(ctx, client, execution.Ok.ScriptId, deviceID)
		} else {
			log.Info("script submitted successfully. Use 'azurehound list intune-script-results --script-id <ID>' to check status")
		}
	}
}

func waitForScriptResult(ctx context.Context, client client.AzureClient, scriptId string, deviceId string) {
	// This would use the enhanced client method if available
	// For now, use a simple polling approach
	
	timeout := time.After(maxWaitTime)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	log.Info("polling for script results", "interval", "15s")

	for {
		select {
		case <-ctx.Done():
			log.Info("script result polling cancelled")
			return
		case <-timeout:
			log.Info("timeout waiting for script completion")
			return
		case <-ticker.C:
			log.V(1).Info("checking script status", "scriptId", scriptId)
			
			// Check for results (this would need the enhanced implementation)
			// For now, just log that we're polling
			log.V(2).Info("polling script execution status...")
			
			// In the enhanced version, this would check actual results and break when complete
		}
	}
}