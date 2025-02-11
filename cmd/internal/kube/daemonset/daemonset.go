package daemonset

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
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

	// When agent will receive pod deleted event
	PodTerminated

	// When apidump process is stopped for the pod
	TrafficMonitoringStopped

	// Final stage after which pod will be removed from the map
	PodRemovedFromMap
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
	PodCreds      PodCreds

	// for state management
	PodTrafficMonitorStage PodTrafficMonitorStage
	StageChangeMutex       *sync.Mutex

	// send stop signal to apidump process
	StopChan chan error
}

func (p *PodArgs) setPodTrafficMonitorStage(stage PodTrafficMonitorStage) {
	p.StageChangeMutex.Lock()
	defer p.StageChangeMutex.Unlock()
	p.PodTrafficMonitorStage = stage
}

func (p *PodArgs) validatePodTrafficMonitorStage(
	nextStage PodTrafficMonitorStage,
	allowedPriorStages ...PodTrafficMonitorStage,
) (bool, error) {
	if slices.Contains(allowedPriorStages, p.PodTrafficMonitorStage) {
		return false, nil
	}

	if p.PodTrafficMonitorStage == nextStage {
		printer.Debugf("API dump process for pod %s is already in state %d", p.PodName, nextStage)
		return true, nil
	}

	return false, errors.New(fmt.Sprintf("Invalid prior state for pod %s: %d", p.PodName,
		p.PodTrafficMonitorStage))
}

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

func (d *Daemonset) getPodArgsFromMap(podName string) (*PodArgs, error) {
	var podArgs *PodArgs
	if p, ok := d.PodArgsByNameMap.Load(podName); ok {
		podArgs = p.(*PodArgs)
	} else {
		return podArgs, errors.Errorf("podArgs not found for podName: %s", podName)
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

func (d *Daemonset) StartProcessInExistingPods() error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) KubernetesEventsWorker() {
	// Not implemented
}

func (d *Daemonset) checkPodsHealth() {
	var podNames []string
	d.PodArgsByNameMap.Range(func(k, v interface{}) bool {
		e := v.(*PodArgs)
		podNames = append(podNames, e.PodName)
		return true
	})

	podStatuses, err := d.KubeClient.GetPodsStatus(podNames)
	if err != nil {
		printer.Errorf("failed to get pods status: %v", err)
		return
	}

	for podName, podStatus := range podStatuses {
		if podStatus == string(coreV1.PodSucceeded) || podStatus == string(coreV1.PodFailed) {
			printer.Infof("pod %s has stopped running", podStatus)

			podArgs, err := d.getPodArgsFromMap(podName)
			if err != nil {
				printer.Errorf("failed to get podArgs for pod %s: %v", podName, err)
				continue
			}

			isSameStage, err := podArgs.validatePodTrafficMonitorStage(PodTerminated, TrafficMonitoringStarted)
			if err != nil {
				printer.Errorf("pod %s is in invalid state %d", podName, podArgs.PodTrafficMonitorStage)
			}
			if isSameStage {
				printer.Errorf("pod %s is already in state %d", podName, podArgs.PodTrafficMonitorStage)
			}

			podArgs.setPodTrafficMonitorStage(PodTerminated)

			d.StopApiDumpProcess(
				podName,
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

func (d *Daemonset) StartApiDumpProcess(podName string) error {
	podArgs, err := d.getPodArgsFromMap(podName)
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
			d.StopApiDumpProcess(podName, err)
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

func (d *Daemonset) StopApiDumpProcess(podName string, err error) error {
	podArgs, err := d.getPodArgsFromMap(podName)
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

	printer.Infof("stopping API dump process for pod %s", podName)
	podArgs.StopChan <- err
	podArgs.setPodTrafficMonitorStage(TrafficMonitoringStopped)

	return nil
}
