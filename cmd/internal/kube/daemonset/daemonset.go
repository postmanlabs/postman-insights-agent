package daemonset

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/integrations/cri_apis"
	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	apiContextTimeout = 20 * time.Second
	agentImage        = "public.ecr.aws/postman/postman-insights-agent:latest"
)

type ApidumpArgs struct {
	InsightsProjectID akid.ServiceID
	InsightsAPIKey    string
}

type Daemonset struct {
	ClusterName string

	KubeClient  kube_apis.KubeClient
	CRIClient   *cri_apis.CriClient
	FrontClient rest.FrontClient

	TelemetryInterval time.Duration
}

func StartDaemonset() error {
	frontClient := rest.NewFrontClient(rest.Domain, telemetry.GetClientID())
	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	clusterName := os.Getenv("POSTMAN_CLUSTER_NAME")
	telemetryInterval := apispec.DefaultTelemetryInterval_seconds * time.Second
	if clusterName == "" {
		printer.Infof(
			"The cluster name is missing. Telemetry will not be sent from this agent, " +
				"it will not be tracked on our end, and it will not appear in the app's " +
				"list of clusters where the agent is running.",
		)
		telemetryInterval = 0
	} else {
		// Send Initial telemetry
		err := frontClient.PostDaemonsetAgentTelemetry(ctx, clusterName)
		if err != nil {
			printer.Errorf("Failed to send daemonset agent telemetry: %v", err)
			printer.Infof(
				"Telemetry will not be sent from this agent, it will not be tracked on our end, " +
					"and it will not appear in the app's list of clusters where the agent is running.",
			)
		}
	}

	kubeClient, err := kube_apis.NewKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create kube client: %w", err)
	}

	criClient, err := cri_apis.NewCRIClient()
	if err != nil {
		return fmt.Errorf("failed to create CRI client: %w", err)
	}

	go func() {
		daemonsetRun := &Daemonset{
			ClusterName:       clusterName,
			KubeClient:        kubeClient,
			CRIClient:         criClient,
			FrontClient:       frontClient,
			TelemetryInterval: telemetryInterval,
		}
		daemonsetRun.Run()
	}()

	return nil
}

func (d *Daemonset) Run() error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) sendTelemetry() {
	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	err := d.FrontClient.PostDaemonsetAgentTelemetry(ctx, d.ClusterName)
	if err != nil {
		printer.Errorf("Failed to send telemetry: %v\n", err)
	}
}

func (d *Daemonset) TelemetryWorker(done <-chan struct{}) {
	if d.TelemetryInterval <= 0 {
		return
	}

	ticker := time.NewTicker(d.TelemetryInterval)

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			d.sendTelemetry()
		}
	}
}

// StartProcessInExistingPods starts apidump process in existing pods
// that do not have the agent sidecar container and required env vars.
func (d *Daemonset) StartProcessInExistingPods() error {
	// Get all pods in the node where the agent is running
	pods, err := d.KubeClient.GetPodsInAgentNode()
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
		args, err := d.inspectPodForEnvVars(pod)
		if err != nil {
			if err.Error() == allRequiredEnvVarsAbsentMsg {
				printer.Debugf("None of the required env vars present, skipping pod: %s", pod.Name)
			} else {
				printer.Errorf("Failed to inspect pod for env vars, pod name: %s, error: %v", pod.Name, err)
			}
			continue
		}

		// TODO(K8S-MNS): Handle all errors and send that at once
		d.StartApiDumpProcess(args)
	}

	return nil
}

func (d *Daemonset) KubernetesEventsWorker(done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case event := <-d.KubeClient.EventWatch.ResultChan():
			switch event.Type {
			case watch.Added:
				printer.Debugf("k8s added event: %v", event.Object)
				if e, ok := event.Object.(*coreV1.Event); ok {
					go d.handlePodAddEvent(e.InvolvedObject.Name)
				}
			case watch.Deleted:
				printer.Debugf("k8s deleted event: %v", event.Object)
				if e, ok := event.Object.(*coreV1.Event); ok {
					go d.handlePodDeleteEvent(e.InvolvedObject.Name)
				}
			}
		}
	}
}

func (d *Daemonset) PodsHealthWorker() {
	// Not implemented
}

func (d *Daemonset) StartApiDumpProcess(args ApidumpArgs) error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) StopApiDumpProcess(podName string) error {
	return fmt.Errorf("not implemented")
}
