package cmd

import (
	"context"
	"github.com/bloodhoundad/azurehound/v2/client"
	"github.com/bloodhoundad/azurehound/v2/client/query"
	"github.com/bloodhoundad/azurehound/v2/enums"
	"github.com/bloodhoundad/azurehound/v2/models"
	"github.com/bloodhoundad/azurehound/v2/panicrecovery"
	"github.com/bloodhoundad/azurehound/v2/pipeline"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"time"
)

func init() {
	listRootCmd.AddCommand(listUnifiedRoleEligibilityScheduleInstanceCmd)
}

var listUnifiedRoleEligibilityScheduleInstanceCmd = &cobra.Command{
	Use:          "unified-role-eligibility-schedule-instances",
	Long:         "Lists Unified Role Eligibility Schedule Instances",
	SilenceUsage: true,
	Run:          listUnifiedRoleEligibilityScheduleInstancesCmdImpl,
}

func listUnifiedRoleEligibilityScheduleInstancesCmdImpl(cmd *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, os.Kill)
	defer gracefulShutdown(stop)

	log.V(1).Info("testing connections")
	azClient := connectAndCreateClient()
	log.Info("collecting azure unified role eligibility schedule instances")
	start := time.Now()
	stream := listRoleEligibilityScheduleInstances(ctx, azClient)
	panicrecovery.HandleBubbledPanic(ctx, stop, log)
	outputStream(ctx, stream)
	duration := time.Since(start)
	log.Info("collection completed", "duration", duration.String())
}

func listRoleEligibilityScheduleInstances(ctx context.Context, client client.AzureClient) <-chan interface{} {
	var (
		out = make(chan interface{})
	)

	go func() {
		defer panicrecovery.PanicRecovery()
		defer close(out)
		count := 0

		for item := range client.ListAzureUnifiedRoleEligibilityScheduleInstances(ctx, query.GraphParams{}) {
			if item.Error != nil {
				log.Error(item.Error, "unable to continue processing unified role eligibility instance schedules")
				return
			} else {
				log.V(2).Info("found unified role eligibility instance schedule", "unifiedRoleEligibilitySchedule", item)
				count++
				result := item.Ok
				if ok := pipeline.SendAny(ctx.Done(), out, azureWrapper[models.RoleEligibilityScheduleInstance]{
					Kind: enums.KindAZRoleEligibilityScheduleInstance,
					Data: models.RoleEligibilityScheduleInstance{
						Id:               result.Id,
						RoleDefinitionId: result.RoleDefinitionId,
						PrincipalId:      result.PrincipalId,
						DirectoryScopeId: result.DirectoryScopeId,
						StartDateTime:    result.StartDateTime,
						TenantId:         client.TenantInfo().TenantId,
					},
				}); !ok {
					return
				}
			}
		}
		log.Info("finished listing unified role eligibility schedule instances")
	}()

	return out
}
