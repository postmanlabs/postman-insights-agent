package daemonset

import (
	"context"
	"fmt"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/integrations/cri_apis"
	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
)

const (
	apiContextTimeout = 20 * time.Second
	agentImage        = "public.ecr.aws/postman/postman-insights-agent:latest"
)

type Args struct {
	ClusterName string
}

type Daemonset struct {
	KubeClient kube_apis.KubeClient
	CRIClient  *cri_apis.CriClient
}

func StartDaemonset(args Args) error {
	frontClient := rest.NewFrontClient(rest.Domain, telemetry.GetClientID())
	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	// Send initial telemetry
	err := frontClient.PostDaemonsetAgentTelemetry(ctx, args.ClusterName)
	if err != nil {
		return err
	}

	kubeClient, err := kube_apis.NewKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create kube client: %w", err)
	}

	criClient, err := cri_apis.NewCRIClient("")
	if err != nil {
		return fmt.Errorf("failed to create CRI client: %w", err)
	}

	errChan := make(chan error)
	go func() {
		daemonsetRun := &Daemonset{
			KubeClient: kubeClient,
			CRIClient:  criClient,
		}
		errChan <- daemonsetRun.Run()
	}()

	return <-errChan
}

func (d *Daemonset) Run() error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) TelemetryWorker() {
	// Not implemented
}

// StartProcessInExistingPods starts apidump process in existing pods
// that do not have the agent sidecar container and required env vars.
func (d *Daemonset) StartProcessInExistingPods() error {
	// Get all pods in the node where the agent is running
	pods, err := d.KubeClient.GetPodsInNode(d.KubeClient.AgentNode)
	if err != nil {
		return fmt.Errorf("failed to get pods in node: %w", err)
	}

	// Filter out pods that do not have the agent sidecar container
	podsWithoutAgentSidecar, err := d.KubeClient.FilterPodsByContainerImage(pods, agentImage, true)
	if err != nil {
		return fmt.Errorf("failed to filter pods by container image: %w", err)
	}

	// Iterate over each pod without the agent sidecar
	for _, pod := range podsWithoutAgentSidecar {
		// Get the UUID of the main container in the pod
		containerUUID, err := d.KubeClient.GetMainContainerUUID(pod)
		if err != nil {
			return fmt.Errorf("failed to get main container UUID: %w", err)
		}

		// Get the environment variables of the main container
		envVars, err := d.CRIClient.GetEnvVars(containerUUID)
		if err != nil {
			return fmt.Errorf("failed to get environment variables for container %s: %w", containerUUID, err)
		}

		var (
			insightsProjectID akid.ServiceID
			insightsAPIKey    string
		)

		// Extract the necessary environment variables
		for key, value := range envVars {
			if key == "POSTMAN_INSIGHTS_PROJECT_ID" {
				err := akid.ParseIDAs(value, &insightsProjectID)
				if err != nil {
					return errors.Wrap(err, "failed to parse project ID")
				}
			} else if key == "POSTMAN_INSIGHTS_API_KEY" {
				insightsAPIKey = value
			}
		}

		// If both the project ID and API key are found, start the API dump process
		if (insightsProjectID != akid.ServiceID{}) && insightsAPIKey != "" {
			//TODO: Call StartApiDumpProcess
		}
	}

	return nil
}

func (d *Daemonset) KubernetesEventsWorker() {
	// Not implemented
}

func (d *Daemonset) PodsHealthWorker() {
	// Not implemented
}

func (d *Daemonset) StartApiDumpProcess() error {
	return fmt.Errorf("not implemented")
}
