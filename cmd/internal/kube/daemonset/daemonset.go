package daemonset

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
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
	done := make(chan struct{})

	// Start the telemetry worker
	go d.TelemetryWorker(done)

	// Start the kubernetes events worker
	go d.KubernetesEventsWorker(done)

	// Start the pods health worker
	go d.PodsHealthWorker(done)

	// Start the process in the existing pods
	err := d.StartProcessInExistingPods()
	if err != nil {
		printer.Errorf("Failed to start process in existing pods, error: %v", err)
		printer.Errorf("Agent will not listen traffic from existing pods")
	}

	printer.Infof("Send SIGINT (Ctrl-C) to stop...\n")

	// Wait for signal to stop
	{
		sig := make(chan os.Signal, 2)
		signal.Notify(sig, os.Interrupt)
		signal.Notify(sig, syscall.SIGTERM)

		// Continue until an interrupt
	DoneWaitingForSignal:
		for {
			select {
			case received := <-sig:
				printer.Stderr.Infof("Received %v, stopping daemonset...\n", received.String())
				break DoneWaitingForSignal
			}
		}
	}

	// Signal all workers to stop
	printer.Debugf("Signaling all workers to stop...\n")
	close(done)

	// Stop all apidump processes
	printer.Debugf("Stopping all apidump processes...\n")
	d.StopAllApiDumpProcesses()

	printer.Infof("Exiting daemonset agent...\n")
	return nil
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

// addPodArgsToMap adds the podArgs to the map with the podUID as the key
// This function ensures that the pod is not already loaded in the map
func (d *Daemonset) addPodArgsToMap(podUID types.UID, args *PodArgs, startingState PodTrafficMonitorState) {
	value, loaded := d.PodArgsByNameMap.LoadOrStore(podUID, args)
	argsFromMap := value.(*PodArgs)
	if loaded {
		err := argsFromMap.changePodTrafficMonitorState(startingState)
		if err != nil {
			printer.Errorf("Failed to change pod state, pod name: %s, from: %d to: %d, error: %v",
				argsFromMap.PodName, argsFromMap.PodTrafficMonitorState, startingState, err)
		}
	} else {
		printer.Errorf("Pod is already loaded in the map and is in state %d", argsFromMap.PodTrafficMonitorState)
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
			d.dumpPodsApiDumpProcessState()
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

		d.addPodArgsToMap(pod.UID, &args, PodDetected)
		err = d.StartApiDumpProcess(pod.UID)
		if err != nil {
			printer.Errorf("Failed to start api dump process, pod name: %s, error: %v", pod.Name, err)
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
				printer.Debugf("Got k8s added event: %v", event.Object)
				if e, ok := event.Object.(*coreV1.Event); ok {
					go d.handlePodAddEvent(e.InvolvedObject.UID)
				}
			case watch.Deleted:
				printer.Debugf("Got k8s deleted event: %v", event.Object)
				if e, ok := event.Object.(*coreV1.Event); ok {
					go d.handlePodDeleteEvent(e.InvolvedObject.UID)
				}
			}
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
			d.pruneStoppedProcesses()
		}
	}
}

func (d *Daemonset) StopAllApiDumpProcesses() {
	d.PodArgsByNameMap.Range(func(k, v interface{}) bool {
		podUID := k.(types.UID)
		podArgs := v.(*PodArgs)

		// Since this state can happen at any time so no check for allowed current states
		err := podArgs.changePodTrafficMonitorState(DaemonSetShutdown)
		if err != nil {
			printer.Errorf("Failed to change pod state, pod name: %s, from: %d to: %d, error: %v",
				podArgs.PodName, podArgs.PodTrafficMonitorState, DaemonSetShutdown, err)
			return true
		}

		err = d.StopApiDumpProcess(podUID, errors.Errorf("Daemonset agent is shutting down, stopping pod: %s", podArgs.PodName))
		if err != nil {
			printer.Errorf("Failed to stop api dump process, pod name: %s, error: %v", podArgs.PodName, err)
		}

		// Remove the pod from the map
		d.PodArgsByNameMap.Delete(podUID)
		return true
	})
}
