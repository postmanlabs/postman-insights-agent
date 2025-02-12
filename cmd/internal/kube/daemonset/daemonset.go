package daemonset

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	apiContextTimeout = 20 * time.Second
	agentImage        = "public.ecr.aws/postman/postman-insights-agent:latest"
)

type PodTrafficMonitorStage int

// These are different stages of pod traffic monitoring
// PodDetected/PodInitialized -> TrafficMonitoringStarted -> TrafficMonitoringFailed/TrafficMonitoringEnded/PodTerminated -> TrafficMonitoringStopped -> PodRemovedFromMap
const (
	// When agent finds an already running pod
	PodDetected PodTrafficMonitorStage = iota

	// When agent will receive pod created event
	PodInitialized

	// When apidump process is started for the pod
	TrafficMonitoringStarted

	// When apidump process is errored for the pod
	TrafficMonitoringFailed

	// When apidump process is ended without any issue for the pod
	TrafficMonitoringEnded

	// When agent will receive pod deleted event or pod is in terminal state while checking status
	PodTerminated

	// When apidump process is stopped for the pod
	TrafficMonitoringStopped

	// Final stage after which pod will be removed from the map
	PodRemovedFromMap
)

type Daemonset struct {
	ClusterName              string
	InsightsReproModeEnabled bool

	KubeClient  kube_apis.KubeClient
	CRIClient   *cri_apis.CriClient
	FrontClient rest.FrontClient

	PodArgsByNameMap sync.Map

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
		return errors.Wrap(err, "failed to create kube client")
	}

	criClient, err := cri_apis.NewCRIClient()
	if err != nil {
		return errors.Wrap(err, "failed to create CRI client")
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

func (d *Daemonset) getPodArgsFromMap(podUID types.UID) (*PodArgs, error) {
	var podArgs *PodArgs
	if p, ok := d.PodArgsByNameMap.Load(podUID); ok {
		podArgs = p.(*PodArgs)
	} else {
		return podArgs, errors.Errorf("podArgs not found for podId: %s", podUID)
	}

	return podArgs, nil
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
		return errors.Wrap(err, "failed to get pods in node")
	}

	// Filter out pods that do not have the agent sidecar container
	podsWithoutAgentSidecar, err := d.KubeClient.FilterPodsByContainerImage(pods, agentImage, true)
	if err != nil {
		return errors.Wrap(err, "failed to filter pods by container image")
	}

	// Iterate over each pod without the agent sidecar
	for _, pod := range podsWithoutAgentSidecar {
		args, err := d.inspectPodForEnvVars(pod)
		if err != nil {
			switch err {
			case allRequiredEnvVarsAbsentErr:
				printer.Debugf("None of the required env vars present, skipping pod: %s", pod.Name)
			case requiredEnvVarMissingErr:
				printer.Errorf("Required env var missing, skipping pod: %s", pod.Name)
			default:
				printer.Errorf("Failed to inspect pod for env vars, pod name: %s, error: %v", pod.Name, err)
			}
			continue
		}

		// Set the pod stage to PodDetected, store it in the map and start the apidump process
		args.setPodTrafficMonitorStage(PodDetected)
		d.PodArgsByNameMap.Store(pod.UID, args)
		err = d.StartApiDumpProcess(pod.UID)
		if err != nil {
			printer.Errorf("failed to start api dump process, pod name: %s, error: %v", pod.Name, err)
		}
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
					go d.handlePodAddEvent(e.InvolvedObject.UID)
				}
			case watch.Deleted:
				printer.Debugf("k8s deleted event: %v", event.Object)
				if e, ok := event.Object.(*coreV1.Event); ok {
					go d.handlePodDeleteEvent(e.InvolvedObject.UID)
				}
			}
		}
	}
}

func (d *Daemonset) checkPodsHealth() {
	var podUIDs []types.UID
	d.PodArgsByNameMap.Range(func(k, _ interface{}) bool {
		podUIDs = append(podUIDs, k.(types.UID))
		return true
	})

	podStatuses, err := d.KubeClient.GetPodsStatusByUIDs(podUIDs)
	if err != nil {
		printer.Errorf("failed to get pods status: %v", err)
		return
	}

	for podUID, podStatus := range podStatuses {
		if podStatus == coreV1.PodSucceeded || podStatus == coreV1.PodFailed {
			printer.Infof("pod %s has stopped running", podStatus)

			podArgs, err := d.getPodArgsFromMap(podUID)
			if err != nil {
				printer.Errorf("failed to get podArgs for podUID %s: %v", podUID, err)
				continue
			}

			isSameStage, err := podArgs.validatePodTrafficMonitorStage(PodTerminated, TrafficMonitoringStarted)
			if err != nil {
				printer.Errorf("pod %s is in invalid state %d", podArgs.PodName, podArgs.PodTrafficMonitorStage)
			}
			if isSameStage {
				printer.Errorf("pod %s is already in state %d", podArgs.PodName, podArgs.PodTrafficMonitorStage)
			}

			podArgs.setPodTrafficMonitorStage(PodTerminated)

			d.StopApiDumpProcess(
				podUID,
				errors.Errorf("pod %s has stopped running, status: %s", podArgs.PodName, podStatus),
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

func (d *Daemonset) StartApiDumpProcess(podUID types.UID) error {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		return err
	}

	isSameStage, err := podArgs.validatePodTrafficMonitorStage(TrafficMonitoringStarted, PodDetected, PodInitialized)
	if isSameStage || err != nil {
		return err
	}

	networkNamespace, err := d.CRIClient.GetNetworkNamespace(podArgs.ContainerUUID)
	if err != nil {
		return errors.Wrapf(err, "failed to get network namespace for pod/containerUUID: %s/%s",
			podArgs.PodName, podArgs.ContainerUUID)
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
			APIKey:                    podArgs.PodCreds.InsightsAPIKey,
			Environment:               podArgs.PodCreds.InsightsEnvironment,
		}),
	}

	podArgs.StopChan = stopChan
	podArgs.setPodTrafficMonitorStage(TrafficMonitoringStarted)
	go func() {
		// If apidump process panics, do not crash the main agent. Instead log the error and stacktrace
		// and stop the apidump process
		defer func() {
			if err := recover(); err != nil {
				printer.Errorf("Panic occurred in apidump process for pod %s, err: %v\n%v\n",
					podArgs.PodName, err, string(debug.Stack()))
				podArgs.setPodTrafficMonitorStage(TrafficMonitoringFailed)
			}
			// It is possible that the apidump process is already stopped and the stopChannel is of no use
			// This is just a safety check
			d.StopApiDumpProcess(podUID, err)
		}()

		if err := apidump.Run(apidumpArgs); err != nil {
			printer.Errorf("Apidump process failed for pod %s: %v", podArgs.PodName, err)
			podArgs.setPodTrafficMonitorStage(TrafficMonitoringFailed)
		} else {
			printer.Infof("Apidump process ended for pod %s", podArgs.PodName)
			podArgs.setPodTrafficMonitorStage(TrafficMonitoringEnded)
		}
	}()

	return nil
}

func (d *Daemonset) StopApiDumpProcess(podUID types.UID, err error) error {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		return err
	}

	isSameStage, stageErr := podArgs.validatePodTrafficMonitorStage(
		TrafficMonitoringStopped,
		PodTerminated, TrafficMonitoringFailed, TrafficMonitoringEnded,
	)
	if isSameStage || stageErr != nil {
		return stageErr
	}

	printer.Infof("stopping API dump process for pod %s", podArgs.PodName)
	podArgs.StopChan <- err
	podArgs.setPodTrafficMonitorStage(TrafficMonitoringStopped)

	return nil
}
