package daemonset

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/go-utils/maps"
	"github.com/postmanlabs/postman-insights-agent/apidump"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/integrations/cri_apis"
	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
)

const (
	apiContextTimeout = 20 * time.Second
)

type PodArgs struct {
	// apidump related fields
	InsightsProjectID        akid.ServiceID
	InsightsAPIKey           string
	InsightsReproModeEnabled bool

	// Pod related fields
	PodName       string
	ContainerUUID string
}

type Daemonset struct {
	ClusterName string

	KubeClient  kube_apis.KubeClient
	CRIClient   *cri_apis.CriClient
	FrontClient rest.FrontClient

	PodNameStopChanMap maps.Map[string, chan error]

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

func (d *Daemonset) StartProcessInExistingPods() error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) KubernetesEventsWorker() {
	// Not implemented
}

func (d *Daemonset) PodsHealthWorker() {
	// Not implemented
}

func (d *Daemonset) StartApiDumpProcess(podArgs PodArgs) error {
	networkNamespace, err := d.CRIClient.GetNetworkNamespace(podArgs.ContainerUUID)
	if err != nil {
		return fmt.Errorf("failed to get network namespace: %w", err)
	}

	// Channel to stop the API dump process
	stopChan := make(chan error)

	apidumpArgs := apidump.Args{
		ClientID:               telemetry.GetClientID(),
		Domain:                 rest.Domain,
		ServiceID:              podArgs.InsightsProjectID,
		TargetNetworkNamespace: networkNamespace,
		ReproMode:              podArgs.InsightsReproModeEnabled,
		StopChan:               stopChan,
	}

	// Put the process stop channel map and start the process in separate go routine
	d.PodNameStopChanMap.Put(podArgs.PodName, stopChan)
	go func() {
		if err := apidump.Run(apidumpArgs); err != nil {
			printer.Errorf("failed to run API dump process for pod %s: %v", podArgs.PodName, err)
		}
	}()

	return nil
}

func (d *Daemonset) StopApiDumpProcess(podName string, err error) error {
	if stopChan, exists := d.PodNameStopChanMap.Get(podName).Get(); exists {
		printer.Infof("stopping API dump process for pod %s", podName)
		stopChan <- err
		d.PodNameStopChanMap.Delete(podName)
		return nil
	} else {
		printer.Errorf("failed to stop API dump process for pod %s: stop channel not found", podName)
		printer.Errorf("Maybe the pod has already been deleted")
	}
	return nil
}
