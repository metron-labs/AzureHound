// File: cmd/list-intune-script-results.go
// Command for listing Intune script execution results

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/bloodhoundad/azurehound/v2/client"
	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/enums"
	"github.com/bloodhoundad/azurehound/v2/panicrecovery"
	"github.com/spf13/cobra"
)

var (
	scriptIDFilter string
	deviceIDFilter string
	showOutput     bool
)

func init() {
	listRootCmd.AddCommand(listIntuneScriptResultsCmd)
	
	listIntuneScriptResultsCmd.Flags().StringVar(&scriptIDFilter, "script-id", "", "Filter by script ID")
	listIntuneScriptResultsCmd.Flags().StringVar(&deviceIDFilter, "device-id", "", "Filter by device ID")
	listIntuneScriptResultsCmd.Flags().BoolVar(&showOutput, "show-output", false, "Include script output in results")
}

var listIntuneScriptResultsCmd = &cobra.Command{
	Use:   "intune-script-results",
	Short: "List Intune script execution results",
	Long: `List the results of executed Intune PowerShell scripts.

Examples:
  # List all script results
  azurehound list intune-script-results --jwt $JWT

  # List results for specific script
  azurehound list intune-script-results --script-id "script-123" --jwt $JWT

  # List results for specific device
  azurehound list intune-script-results --device-id "device-456" --jwt $JWT

  # Include script output
  azurehound list intune-script-results --show-output --jwt $JWT`,
	Run:          listIntuneScriptResultsCmdImpl,
	SilenceUsage: true,
}

func listIntuneScriptResultsCmdImpl(cmd *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, os.Kill)
	defer gracefulShutdown(stop)

	log.V(1).Info("testing connections")
	azClient := connectAndCreateClient()
	log.Info("collecting intune script results...")
	start := time.Now()
	stream := listIntuneScriptResults(ctx, azClient)
	panicrecovery.HandleBubbledPanic(ctx, stop, log)
	outputStream(ctx, stream)
	duration := time.Since(start)
	log.Info("collection completed", "duration", duration.String())
}

func listIntuneScriptResults(ctx context.Context, client client.AzureClient) <-chan interface{} {
	var (
		out = make(chan interface{})
	)

	go func() {
		defer panicrecovery.PanicRecovery()
		defer close(out)

		if scriptIDFilter != "" {
			// Get results for specific script
			listResultsForScript(ctx, client, scriptIDFilter, out)
		} else {
			// Get all scripts and their results
			listAllScriptResults(ctx, client, out)
		}
	}()

	return out
}

func listResultsForScript(ctx context.Context, client client.AzureClient, scriptId string, out chan<- interface{}) {
	params := query.GraphParams{}
	if deviceIDFilter != "" {
		params.Filter = fmt.Sprintf("deviceId eq '%s'", deviceIDFilter)
	}

	count := 0
	for result := range client.GetIntuneScriptResults(ctx, scriptId, params) {
		if result.Error != nil {
			log.Error(result.Error, "unable to get script results", "scriptId", scriptId)
			continue
		}

		// Filter output if requested
		if !showOutput {
			result.Ok.ScriptOutput = "" // Clear output to reduce noise
		}

		log.V(2).Info("found script result", 
			"device", result.Ok.DeviceName,
			"state", result.Ok.RunState,
			"scriptId", scriptId)
		
		count++
		select {
		case out <- NewAzureWrapper(enums.KindAZIntuneScriptResult, result.Ok):
		case <-ctx.Done():
			return
		}
	}
	log.V(1).Info("finished listing script results", "scriptId", scriptId, "count", count)
}

func listAllScriptResults(ctx context.Context, client client.AzureClient, out chan<- interface{}) {
	// First get all scripts
	scriptParams := query.GraphParams{}
	scripts := make([]string, 0)

	for script := range client.ListIntuneDeviceManagementScripts(ctx, scriptParams) {
		if script.Error != nil {
			log.Error(script.Error, "unable to list scripts")
			continue
		}
		scripts = append(scripts, script.Ok.Id)
	}

	log.V(1).Info("found scripts", "count", len(scripts))

	// Then get results for each script
	totalResults := 0
	for _, scriptId := range scripts {
		params := query.GraphParams{}
		if deviceIDFilter != "" {
			params.Filter = fmt.Sprintf("deviceId eq '%s'", deviceIDFilter)
		}

		scriptResults := 0
		for result := range client.GetIntuneScriptResults(ctx, scriptId, params) {
			if result.Error != nil {
				log.Error(result.Error, "unable to get script results", "scriptId", scriptId)
				continue
			}

			// Filter output if requested
			if !showOutput {
				result.Ok.ScriptOutput = "" // Clear output to reduce noise
			}

			log.V(2).Info("found script result", 
				"device", result.Ok.DeviceName,
				"state", result.Ok.RunState,
				"scriptId", scriptId)
			
			scriptResults++
			totalResults++
			select {
			case out <- NewAzureWrapper(enums.KindAZIntuneScriptResult, result.Ok):
			case <-ctx.Done():
				return
			}
		}
		
		if scriptResults > 0 {
			log.V(1).Info("finished script results", "scriptId", scriptId, "count", scriptResults)
		}
	}
	
	log.V(1).Info("finished listing all script results", "totalCount", totalResults)
}