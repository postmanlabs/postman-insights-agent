package daemonset

import (
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/deployment"
	"github.com/postmanlabs/postman-insights-agent/printer"
	coreV1 "k8s.io/api/core/v1"
)

var (
	allRequiredEnvVarsAbsentErr = errors.New("All required environment variables are absent.")
	requiredEnvVarMissingErr    = errors.New("One or more required environment variables are missing. " +
		"Ensure all the necessary environment variables are set correctly via ConfigMaps or Secrets.")
)

// handlePodAddEvent handles the event when a pod is added to the Kubernetes cluster.
// It performs the following steps:
// 1. Check if the pod does not have the agent sidecar container.
// 3. Adds the pod arguments to a map and change state to PodPending.
func (d *Daemonset) handlePodAddEvent(pod coreV1.Pod) {

	// Filter out pods that do not have the agent sidecar container
	podsWithoutAgentSidecar, err := d.KubeClient.FilterPodsByContainerImage([]coreV1.Pod{pod}, agentImage, true)
	if err != nil {
		printer.Errorf("Failed to filter pod by container image: %v\n", err)
		return
	}
	if len(podsWithoutAgentSidecar) == 0 {
		printer.Infof("Pod already has agent sidecar container, skipping, podUID: %s\n", pod.UID)
		return
	}

	// Empty podArgs object for PodPending state
	args := NewPodArgs(pod.Name)
	printer.Debugf("Pod is in pending state. Adding it to the map, pod name: %s\n", pod.Name)

	err = d.addPodArgsToMap(pod.UID, args, PodPending)
	if err != nil {
		printer.Errorf("Failed to add pod args to map, pod name: %s, error: %v\n", pod.Name, err)
	}
}

// handlePodDeleteEvent handles the deletion event of a pod.
// It performs the following actions:
// 1. Retrieves the pod arguments from the internal map using the pod UID.
// 2. Changes the pod traffic monitor state to PodSucceeded/PodFailed/PodTerminated.
// 3. Stops the API dump process for the pod.
func (d *Daemonset) handlePodDeleteEvent(pod coreV1.Pod) {
	// Check if we are interested in the pod
	podArgs, err := d.getPodArgsFromMap(pod.UID)
	if err != nil {
		printer.Debugf("Failed to get podArgs for pod UID %s: %v\n", pod.UID, err)
		return
	}

	if podArgs.isEndState() {
		printer.Debugf("Pod %s already stopped monitoring, state: %s\n", podArgs.PodName, podArgs.PodTrafficMonitorState)
		return
	}

	var podStatus PodTrafficMonitorState
	switch pod.Status.Phase {
	case coreV1.PodSucceeded:
		podStatus = PodSucceeded
	case coreV1.PodFailed:
		podStatus = PodFailed
	default:
		printer.Errorf("Pod status is in unknown state, pod name: %s, status: %s\n", podArgs.PodName, pod.Status.Phase)
		podStatus = PodTerminated
	}

	err = podArgs.changePodTrafficMonitorState(podStatus, TrafficMonitoringRunning)
	if err != nil {
		printer.Errorf("Failed to change pod state, pod name: %s, from: %s to: %s, error: %v\n",
			podArgs.PodName, podArgs.PodTrafficMonitorState, podStatus, err)
		return
	}

	err = d.StopApiDumpProcess(pod.UID, errors.Errorf("got pod delete event, pod: %s", podArgs.PodName))
	if err != nil {
		printer.Errorf("Failed to stop api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
	}
}

// handlePodModifyEvent handles the modification event of a pod.
// It performs the following actions:
// 1. Retrieves the pod arguments from the internal map using the pod UID.
// 2. Changes the pod traffic monitor state to PodRunning if the pod status is running.
// 3. Inspects the pod for required environment variables.
// 4. Starts the API dump process for the pod.
func (d *Daemonset) handlePodModifyEvent(pod coreV1.Pod) {
	// Check if we are interested in the pod
	podArgs, err := d.getPodArgsFromMap(pod.UID)
	if err != nil {
		printer.Debugf("Failed to get podArgs for pod UID %s: %v\n", pod.UID, err)
		return
	}

	// Check if the pods status is running
	if pod.Status.Phase == coreV1.PodRunning && podArgs.PodTrafficMonitorState == PodPending {
		printer.Debugf("Pod is running, starting api dump process, pod name: %s\n", podArgs.PodName)
		err := d.inspectPodForEnvVars(pod, podArgs)
		if err != nil {
			switch err {
			case allRequiredEnvVarsAbsentErr:
				printer.Debugf("None of the required env vars present, skipping pod: %s\n", pod.Name)
			case requiredEnvVarMissingErr:
				printer.Errorf("Required env var missing, skipping pod: %s\n", pod.Name)
			default:
				printer.Errorf("Failed to inspect pod for env vars, pod name: %s, error: %v\n", pod.Name, err)
			}

			// remove pod from map if required env vars are missing
			d.PodArgsByNameMap.Delete(pod.UID)
			return
		}

		err = podArgs.changePodTrafficMonitorState(PodRunning, PodPending)
		if err != nil {
			printer.Errorf("Failed to change pod state, pod name: %s, from: %s to: %s, error: %v\n",
				podArgs.PodName, podArgs.PodTrafficMonitorState, PodRunning, err)
			return
		}

		// Start monitoring the pod
		err = d.StartApiDumpProcess(pod.UID)
		if err != nil {
			printer.Errorf("Failed to start api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
		}
	}
}

// inspectPodForEnvVars inspects a given pod to extract specific environment variables
// required for the Postman Insights project. It retrieves the UUID of the main container
// in the pod, fetches the environment variables of that container, and extracts the
// necessary variables such as the project ID, API key, and environment.
func (d *Daemonset) inspectPodForEnvVars(pod coreV1.Pod, podArgs *PodArgs) error {
	// Get the UUID of the main container in the pod
	containerUUID, err := d.KubeClient.GetMainContainerUUID(pod)
	if err != nil {
		return errors.Wrapf(err, "failed to get main container UUID for pod: %s", pod.Name)
	}

	// Get the environment variables of the main container
	envVars, err := d.CRIClient.GetEnvVars(containerUUID)
	if err != nil {
		return errors.Wrapf(err, "failed to get environment variables for pod/container : %s/%s", pod.Name, containerUUID)
	}

	var (
		insightsProjectID akid.ServiceID
		insightsAPIKey    string
	)

	// Extract the necessary environment variables
	for key, value := range envVars {
		switch key {
		case POSTMAN_INSIGHTS_PROJECT_ID:
			err := akid.ParseIDAs(value, &insightsProjectID)
			if err != nil {
				return errors.Wrap(err, "failed to parse project ID")
			}
		case POSTMAN_INSIGHTS_API_KEY:
			insightsAPIKey = value
		}
	}

	if (insightsProjectID == akid.ServiceID{}) && insightsAPIKey == "" {
		return allRequiredEnvVarsAbsentErr
	}

	if (insightsProjectID == akid.ServiceID{}) {
		printer.Errorf("Project ID is missing, set it using the environment variable %s, pod name: %s\n", POSTMAN_INSIGHTS_PROJECT_ID, pod.Name)
		return requiredEnvVarMissingErr
	}

	if insightsAPIKey == "" {
		printer.Errorf("API key is missing, set it using the environment variable %s, pod name: %s\n", POSTMAN_INSIGHTS_API_KEY, pod.Name)
		return requiredEnvVarMissingErr
	}

	// Set the trace tags for apidump process from the pod info
	deployment.SetK8sTraceTags(pod, podArgs.TraceTags)

	podArgs.ContainerUUID = containerUUID
	podArgs.InsightsProjectID = insightsProjectID
	podArgs.PodCreds = PodCreds{
		InsightsAPIKey:      insightsAPIKey,
		InsightsEnvironment: d.InsightsEnvironment,
	}

	return nil
}
