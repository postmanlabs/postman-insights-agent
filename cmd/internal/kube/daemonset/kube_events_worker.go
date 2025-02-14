package daemonset

import (
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

var (
	allRequiredEnvVarsAbsentErr = errors.New("All required environment variables are absent.")
	requiredEnvVarMissingErr    = errors.New("One or more required environment variables are missing. " +
		"Ensure all the necessary environment variables are set correctly via ConfigMaps or Secrets.")
)

// handlePodAddEvent handles the event when a pod is added to the Kubernetes cluster.
// It performs the following steps:
// 1. Retrieves the pod by its UID.
// 4. Filters out pods that already have the agent sidecar container.
// 5. Inspects the pod for required environment variables.
// 6. Adds the pod arguments to a map and starts the API dump process.
func (d *Daemonset) handlePodAddEvent(podUID types.UID) {
	pods, err := d.KubeClient.GetPodsByUIDs([]types.UID{podUID})
	if err != nil {
		printer.Errorf("Failed to get pod for k8s added event, podUID: %s, error: %v\n", podUID, err)
		return
	}
	if len(pods) == 0 {
		printer.Infof("No pod found for k8s added event, podUID: %s\n", podUID)
		return
	}
	if len(pods) > 1 {
		printer.Errorf("Multiple pods found for single UID, this should not happen, podUID: %s\n", podUID)
		return
	}

	// Filter out pods that do not have the agent sidecar container
	podsWithoutAgentSidecar, err := d.KubeClient.FilterPodsByContainerImage(pods, agentImage, true)
	if err != nil {
		printer.Errorf("Failed to filter pod by container image: %v\n", err)
		return
	}
	if len(podsWithoutAgentSidecar) == 0 {
		printer.Infof("Pod already has agent sidecar container, skipping, podUID: %s\n", podUID)
		return
	}

	pod := podsWithoutAgentSidecar[0]

	args, err := d.inspectPodForEnvVars(pod)
	if err != nil {
		switch err {
		case allRequiredEnvVarsAbsentErr:
			printer.Debugf("None of the required env vars present, skipping pod: %s\n", pod.Name)
		case requiredEnvVarMissingErr:
			printer.Errorf("Required env var missing, skipping pod: %s\n", pod.Name)
		default:
			printer.Errorf("Failed to inspect pod for env vars, pod name: %s, error: %v\n", pod.Name, err)
		}
		return
	}

	d.addPodArgsToMap(pod.UID, &args, PodInitialized)
	err = d.StartApiDumpProcess(pod.UID)
	if err != nil {
		printer.Errorf("Failed to start api dump process, pod name: %s, error: %v\n", pod.Name, err)
	}
}

// handlePodDeleteEvent handles the deletion event of a pod.
// It performs the following actions:
// 1. Retrieves the pod arguments from the internal map using the pod UID.
// 2. Changes the pod traffic monitor state to PodTerminated.
// 3. Stops the API dump process for the pod.
func (d *Daemonset) handlePodDeleteEvent(podUID types.UID) {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		printer.Errorf("Failed to get podArgs for pod UID %s: %v\n", podUID, err)
		return
	}

	err = podArgs.changePodTrafficMonitorState(PodTerminated, TrafficMonitoringStarted)
	if err != nil {
		printer.Errorf("Failed to change pod state, pod name: %s, from: %s to: %s, error: %v\n",
			podArgs.PodName, podArgs.PodTrafficMonitorState, PodTerminated, err)
		return
	}

	err = d.StopApiDumpProcess(podUID, errors.Errorf("got pod delete event, pod: %s", podArgs.PodName))
	if err != nil {
		printer.Errorf("Failed to stop api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
	}
}

// inspectPodForEnvVars inspects a given pod to extract specific environment variables
// required for the Postman Insights project. It retrieves the UUID of the main container
// in the pod, fetches the environment variables of that container, and extracts the
// necessary variables such as the project ID, API key, and environment.
func (d *Daemonset) inspectPodForEnvVars(pod coreV1.Pod) (PodArgs, error) {
	// Get the UUID of the main container in the pod
	containerUUID, err := d.KubeClient.GetMainContainerUUID(pod)
	if err != nil {
		return PodArgs{}, errors.Wrapf(err, "failed to get main container UUID for pod: %s", pod.Name)
	}

	// Get the environment variables of the main container
	envVars, err := d.CRIClient.GetEnvVars(containerUUID)
	if err != nil {
		return PodArgs{}, errors.Wrapf(err, "failed to get environment variables for pod/container : %s/%s", pod.Name, containerUUID)
	}

	var (
		insightsProjectID   akid.ServiceID
		insightsAPIKey      string
		insightsEnvironment string
	)

	// Extract the necessary environment variables
	for key, value := range envVars {
		switch key {
		case string(POSTMAN_INSIGHTS_PROJECT_ID):
			err := akid.ParseIDAs(value, &insightsProjectID)
			if err != nil {
				return PodArgs{}, errors.Wrap(err, "failed to parse project ID")
			}
		case string(POSTMAN_INSIGHTS_API_KEY):
			insightsAPIKey = value
		case string(POSTMAN_INSIGHTS_ENV):
			insightsEnvironment = value
		}
	}

	if (insightsProjectID == akid.ServiceID{}) && insightsAPIKey == "" {
		return PodArgs{}, allRequiredEnvVarsAbsentErr
	}

	if (insightsProjectID == akid.ServiceID{}) {
		printer.Errorf("Project ID is missing, set it using the environment variable %s, pod name: %s\n", POSTMAN_INSIGHTS_PROJECT_ID, pod.Name)
		return PodArgs{}, requiredEnvVarMissingErr
	}

	if insightsAPIKey == "" {
		printer.Errorf("API key is missing, set it using the environment variable %s, pod name: %s\n", POSTMAN_INSIGHTS_API_KEY, pod.Name)
		return PodArgs{}, requiredEnvVarMissingErr
	}

	args := PodArgs{
		PodName:           pod.Name,
		ContainerUUID:     containerUUID,
		InsightsProjectID: insightsProjectID,
		PodCreds: PodCreds{
			InsightsAPIKey:      insightsAPIKey,
			InsightsEnvironment: insightsEnvironment,
		},
		// though 1 buffer size is enough, keeping 2 for safety
		StopChan: make(chan error, 2),
	}

	return args, nil
}
