package daemonset

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/go-utils/maps"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/apidump"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/integrations/cri_apis"
	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	coreV1 "k8s.io/api/core/v1"
)

const (
	apiContextTimeout = 20 * time.Second
)

type PodCreds struct {
	InsightsAPIKey      string
	InsightsEnvironment string
}

type PodArgs struct {
	// apidump related fields
	InsightsProjectID        akid.ServiceID
	InsightsReproModeEnabled bool

	// Pod related fields
	PodName       string
	ContainerUUID string
}

type Daemonset struct {
	ClusterName              string
	InsightsReproModeEnabled bool

	KubeClient  kube_apis.KubeClient
	CRIClient   *cri_apis.CriClient
	FrontClient rest.FrontClient

	PodNameStopChanMap maps.Map[string, chan error]

	PodHealthCheckInterval time.Duration
	TelemetryInterval      time.Duration
}

func StartDaemonset() error {
	// Initialize the front client
	postmanInsightsVerificationToken := os.Getenv("POSTMAN_INSIGHTS_VERIFICATION_TOKEN")
	frontClient := rest.NewFrontClient(
		rest.Domain,
		telemetry.GetClientID(),
		rest.DaemonsetAuthHandler(postmanInsightsVerificationToken),
	)
	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	// Send initial telemetry
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
			printer.Errorf("Failed to send initial daemonset agent telemetry: %v", err)
			printer.Infof(
				"Agent will try to send telemetry again, if the error still persists, agent " +
					"will not be tracked on our end, and it will not appear in the app's list of " +
					"clusters where the agent is running.",
			)
		}
	}

	insightsReproModeEnabled := os.Getenv("POSTMAN_INSIGHTS_REPRO_MODE_ENABLED") == "true"

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
			ClusterName:              clusterName,
			InsightsReproModeEnabled: insightsReproModeEnabled,
			KubeClient:               kubeClient,
			CRIClient:                criClient,
			FrontClient:              frontClient,
			TelemetryInterval:        telemetryInterval,
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

func (d *Daemonset) checkPodsHealth() {
	podNames := d.PodNameStopChanMap.Keys()

	podStatuses, err := d.KubeClient.GetPodsStatus(podNames)
	if err != nil {
		printer.Errorf("failed to get pods status: %v", err)
		return
	}

	for podName, podStatus := range podStatuses {
		if podStatus == string(coreV1.PodSucceeded) || podStatus == string(coreV1.PodFailed) {
			printer.Infof("pod %s has stopped running", podStatus)
			d.StopApiDumpProcess(
				podStatus,
				fmt.Errorf("pod %s has stopped running, status: %s", podName, podStatus),
			)
		}
	}
}

func (d *Daemonset) PodsHealthWorker(done <-chan struct{}) {
	if d.PodHealthCheckInterval <= 0 {
		return
	}

	ticker := time.NewTicker(d.PodHealthCheckInterval)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			d.checkPodsHealth()
		}
	}

}

func (d *Daemonset) StartApiDumpProcess(podArgs PodArgs, podCreds PodCreds) error {
	networkNamespace, err := d.CRIClient.GetNetworkNamespace(podArgs.ContainerUUID)
	if err != nil {
		return errors.Wrapf(err, "failed to get network namespace for pod/containerUUID: %s/%s", podArgs.PodName, podArgs.ContainerUUID)
	}

	// Channel to stop the API dump process
	stopChan := make(chan error)

	apidumpArgs := apidump.Args{
		ClientID:  telemetry.GetClientID(),
		Domain:    rest.Domain,
		ServiceID: podArgs.InsightsProjectID,
		ReproMode: d.InsightsReproModeEnabled,
		DaemonsetArgs: optionals.Some(apidump.DaemonsetArgs{
			TargetNetworkNamespaceOpt: networkNamespace,
			StopChan:                  stopChan,
			APIKey:                    podCreds.InsightsAPIKey,
			Environment:               podCreds.InsightsEnvironment,
		}),
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
