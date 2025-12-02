package daemonset

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
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

type DaemonsetArgs struct {
	ReproMode bool
	RateLimit float64
}

type Daemonset struct {
	ClusterName              string
	InsightsEnvironment      string
	InsightsReproModeEnabled bool
	InsightsRateLimit        float64

	APIKey      string
	WorkspaceID string

	KubeClient  kube_apis.KubeClient
	CRIClient   *cri_apis.CriClient
	FrontClient rest.FrontClient

	// Note: Only filtered pods are stored in this map, i.e., they have required env vars
	// and do not have the agent sidecar container
	PodArgsByNameMap sync.Map

	// WaitGroup to wait for all apidump processes to stop
	ApidumpProcessesWG sync.WaitGroup

	PodHealthCheckInterval time.Duration
	TelemetryInterval      time.Duration
}

func StartDaemonset(args DaemonsetArgs) error {
	// Check if the agent is running in a linux environment
	if runtime.GOOS != "linux" {
		return errors.New("This command is only supported on linux images")
	}

	// Initialize the front client
	postmanInsightsVerificationToken := os.Getenv(POSTMAN_INSIGHTS_VERIFICATION_TOKEN)
	frontClient := rest.NewFrontClient(
		rest.Domain,
		telemetry.GetClientID(),
		rest.DaemonsetAuthHandler(postmanInsightsVerificationToken),
		nil,
	)
	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	// Send initial telemetry
	clusterName := os.Getenv(POSTMAN_INSIGHTS_CLUSTER_NAME)
	telemetryInterval := DefaultTelemetryInterval
	if clusterName == "" {
		printer.Infof(
			"The cluster name is missing. Telemetry will not be sent from this agent, " +
				"it will not be tracked on our end, and it will not appear in the app's " +
				"list of clusters where the agent is running.\n",
		)
		telemetryInterval = 0
	} else {
		// Send Initial telemetry
		err := frontClient.PostDaemonsetAgentTelemetry(ctx, clusterName)
		if err != nil {
			printer.Errorf("Failed to send initial daemonset agent telemetry: %v\n", err)
			printer.Infof(
				"Agent will try to send telemetry again, if the error still persists, agent " +
					"will not be tracked on our end, and it will not appear in the app's list of " +
					"clusters where the agent is running.\n",
			)
		}
	}

	kubeClient, err := kube_apis.NewKubeClient()
	if err != nil {
		return errors.Wrap(err, "failed to create kube client")
	}

	criClient, err := cri_apis.NewCRIClient()
	if err != nil {
		return errors.Wrap(err, "failed to create CRI client")
	}

	daemonsetRun := &Daemonset{
		ClusterName:              clusterName,
		InsightsEnvironment:      os.Getenv(POSTMAN_INSIGHTS_ENV),
		InsightsReproModeEnabled: args.ReproMode,
		InsightsRateLimit:        args.RateLimit,
		APIKey:                   os.Getenv(POSTMAN_INSIGHTS_API_KEY),
		WorkspaceID:              os.Getenv(POSTMAN_INSIGHTS_WORKSPACE_ID),
		KubeClient:               kubeClient,
		CRIClient:                criClient,
		FrontClient:              frontClient,
		TelemetryInterval:        telemetryInterval,
		PodHealthCheckInterval:   DefaultPodHealthCheckInterval,
	}
	if err := daemonsetRun.Run(); err != nil {
		return cmderr.AkitaErr{Err: err}
	}

	return nil
}

// Run starts the Daemonset and its workers, and waits for a termination signal.
// It performs the following steps:
// 1. Starts all the workers.
// 4. Starts the process in the existing pods.
// 5. Waits for a termination signal (SIGINT or SIGTERM).
// 6. Signals all workers to stop.
// 7. Stops all apidump processes.
// 8. Exits the daemonset agent.
func (d *Daemonset) Run() error {
	printer.Infof("Starting daemonset agent...\n")
	done := make(chan struct{})

	// Start the telemetry worker
	printer.Infof("Starting telemetry worker...\n")
	go d.TelemetryWorker(done)

	// Start the kubernetes events worker
	printer.Infof("Starting kubernetes pods events worker...\n")
	go d.KubernetesPodEventsWorker(done)

	// Start the pods health worker
	printer.Infof("Starting pods health worker...\n")
	go d.PodsHealthWorker(done)

	// Start the process in the existing pods
	printer.Infof("Starting process in existing pods...\n")
	err := d.StartProcessInExistingPods()
	if err != nil {
		printer.Errorf("Failed to start process in existing pods, error: %v\n", err)
		printer.Errorf("Agent will not listen traffic from existing pods\n")
	}

	printer.Infof("Send SIGINT (Ctrl-C) to stop...\n")

	// Wait for signal to stop
	{
		sig := make(chan os.Signal, 2)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

		// Continue until an interrupt
		for received := range sig {
			printer.Stderr.Infof("Received %v, stopping daemonset...\n", received.String())
			break
		}
	}

	// Signal all workers to stop
	printer.Debugf("Signaling all workers to stop...\n")
	close(done)

	// Stop all apidump processes
	printer.Debugf("Stopping all apidump processes...\n")
	d.StopAllApiDumpProcesses()

	// Stop K8s Watcher
	printer.Debugf("Stopping k8s watcher...\n")
	d.KubeClient.Close()

	printer.Infof("Exiting daemonset agent...\n")
	return nil
}

// getPodArgsFromMap retrieves the PodArgs associated with the given podUID from the PodArgsByNameMap.
// If the PodArgs are found, they are returned. Otherwise, an error is returned indicating that the PodArgs
// were not found for the specified podUID.
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
func (d *Daemonset) addPodArgsToMap(podUID types.UID, args *PodArgs, startingState PodTrafficMonitorState) error {
	value, loaded := d.PodArgsByNameMap.LoadOrStore(podUID, args)
	argsFromMap := value.(*PodArgs)
	if !loaded {
		err := argsFromMap.changePodTrafficMonitorState(startingState)
		if err != nil {
			return errors.Wrapf(err, "failed to change pod state, pod name: %s, from: %s to: %s",
				argsFromMap.PodName, argsFromMap.PodTrafficMonitorState, startingState)
		}
	} else {
		return errors.Errorf("pod is already loaded in the map and is in state %s", argsFromMap.PodTrafficMonitorState)
	}

	return nil
}

// TelemetryWorker starts a worker that periodically sends telemetry data and dumps the state of the Pods API dump process.
// The worker runs until the provided done channel is closed.
func (d *Daemonset) TelemetryWorker(done <-chan struct{}) {
	if d.TelemetryInterval <= 0 {
		printer.Debugf("Telemetry interval is set to 0, telemetry worker will not run\n")
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
		// Empty pod_args object for PodPending state
		args := NewPodArgs(pod.Name)
		err := d.inspectPodForEnvVars(pod, args)
		if err != nil {
			switch e := err.(type) {
			case *allRequiredEnvVarsAbsentError:
				printer.Debugf(e.Error())
			case *requiredEnvVarMissingError:
				printer.Errorf(e.Error())
			default:
				printer.Errorf("Failed to inspect pod for env vars, pod name: %s, error: %v\n", pod.Name, err)
			}
			continue
		}

		err = d.addPodArgsToMap(pod.UID, args, PodRunning)
		if err != nil {
			printer.Errorf("Failed to add pod args to map, pod name: %s, error: %v\n", pod.Name, err)
			continue
		}

		err = d.StartApiDumpProcess(pod.UID)
		if err != nil {
			printer.Errorf("Failed to start api dump process, pod name: %s, error: %v\n", pod.Name, err)
		}
	}

	return nil
}

// KubernetesPodEventsWorker listens for Kubernetes events and handles them accordingly.
// It runs indefinitely until the provided done channel is closed.
func (d *Daemonset) KubernetesPodEventsWorker(done <-chan struct{}) {
	for {
		select {
		case <-done:
			printer.Debugf("Kubernetes pod events worker stopped\n")
			return
		case event := <-d.KubeClient.PodEventWatch.ResultChan():
			switch event.Type {
			case watch.Added:
				printer.Debugf("Got k8s pod added event: %v\n", event.Object)
				if p, ok := event.Object.(*coreV1.Pod); ok {
					go d.handlePodAddEvent(*p)
				}
			// A pod is deleted
			case watch.Deleted:
				printer.Debugf("Got k8s pod deleted event: %v\n", event.Object)
				if p, ok := event.Object.(*coreV1.Pod); ok {
					go d.handlePodDeleteEvent(*p)
				}
			case watch.Modified:
				printer.Debugf("Got k8s pod modified event: %v\n", event.Object)
				if p, ok := event.Object.(*coreV1.Pod); ok {
					go d.handlePodModifyEvent(*p)
				}
			case watch.Error:
				printer.Errorf("Got k8s watcher error event: %v\n", event.Object)
			}
		}
	}
}

// PodsHealthWorker periodically checks the health of the pods and prunes stopped processes.
// It runs until the provided done channel is closed.
func (d *Daemonset) PodsHealthWorker(done <-chan struct{}) {
	if d.PodHealthCheckInterval <= 0 {
		printer.Debugf("Pod health check interval is set to 0, pods health worker will not run\n")
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

// StopAllApiDumpProcesses stops all API dump processes for the Daemonset.
// It iterates over the PodArgsByNameMap and performs the following actions for each pod:
// 1. Changes the pod's traffic monitor state to DaemonSetShutdown.
// 2. Stops the API dump process for the pod.
// 3. Logs any errors encountered during the state change or stopping process.
// 4. Removes the pod from the PodArgsByNameMap.
// 5. Wait for all the apidump processes to stop.
func (d *Daemonset) StopAllApiDumpProcesses() {
	d.PodArgsByNameMap.Range(func(k, v interface{}) bool {
		podUID := k.(types.UID)
		podArgs := v.(*PodArgs)

		// Since this state can happen at any time so no check for allowed current states
		err := podArgs.changePodTrafficMonitorState(DaemonSetShutdown)
		if err != nil {
			printer.Errorf("Failed to change pod state, pod name: %s, from: %s to: %s, error: %v\n",
				podArgs.PodName, podArgs.PodTrafficMonitorState, DaemonSetShutdown, err)
			return true
		}

		err = d.SignalApiDumpProcessToStop(podUID, errors.Errorf("Daemonset agent is shutting down, stopping pod: %s", podArgs.PodName))
		if err != nil {
			printer.Errorf("Failed to stop api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
		}

		// Remove the pod from the map
		d.PodArgsByNameMap.Delete(podUID)
		return true
	})

	// Wait for all apidump processes to stop
	printer.Debugf("Waiting for all apidump processes to stop...\n")
	d.ApidumpProcessesWG.Wait()
}
