package daemonset

import (
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	coreV1 "k8s.io/api/core/v1"
)

var (
	allRequiredEnvVarsAbsentErr = errors.New("All required environment variables are absent.")
	requiredEnvVarMissingErr    = errors.New("One or more required environment variables are missing. " +
		"Ensure all the necessary environment variables are set correctly via ConfigMaps or Secrets.")
)

func (d *Daemonset) handlePodAddEvent(podName string) {
	pods, err := d.KubeClient.GetPods([]string{podName})
	if err != nil {
		printer.Errorf("failed to get pod for k8s added event, pod name: %s, error: %v", podName, err)
		return
	}
	if len(pods) == 0 {
		printer.Infof("no pod found for k8s added event, pod name: %s", podName)
		return
	}

	// Filter out pods that do not have the agent sidecar container
	podsWithoutAgentSidecar, err := d.KubeClient.FilterPodsByContainerImage(pods, agentImage, true)
	if err != nil {
		printer.Errorf("failed to filter pod by container image: %v", err)
		return
	}
	if len(podsWithoutAgentSidecar) == 0 {
		printer.Infof("pod already has agent sidecar container, skipping, pod name: %s", podName)
		return
	}

	args, err := d.inspectPodForEnvVars(podsWithoutAgentSidecar[0])
	if err != nil {
		switch err {
		case allRequiredEnvVarsAbsentErr:
			printer.Debugf("None of the required env vars present, skipping pod: %s", podName)
		case requiredEnvVarMissingErr:
			printer.Errorf("Required env var missing, skipping pod: %s", podName)
		default:
			printer.Errorf("Failed to inspect pod for env vars, pod name: %s, error: %v", podName, err)
		}
		return
	}

	args.setPodTrafficMonitorStage(PodInitialized)

	err = d.StartApiDumpProcess(podName)
	if err != nil {
		printer.Errorf("failed to start api dump process, pod name: %s, error: %v", podName, err)
	}
}

func (d *Daemonset) handlePodDeleteEvent(podName string) {
	podArgs, err := d.getPodArgsFromMap(podName)
	if err != nil {
		printer.Errorf("failed to get podArgs for pod %s: %v", podName, err)
		return
	}

	isSameStage, err := podArgs.validatePodTrafficMonitorStage(PodTerminated, TrafficMonitoringStarted)
	if err != nil {
		printer.Errorf("pod %s is in invalid state %d", podName, podArgs.PodTrafficMonitorStage)
	}
	if isSameStage {
		printer.Errorf("pod %s is already in state %d", podName, podArgs.PodTrafficMonitorStage)
	}

	podArgs.setPodTrafficMonitorStage(PodTerminated)

	err = d.StopApiDumpProcess(podName, errors.Errorf("got pod delete event, pod: %s", podName))
	if err != nil {
		printer.Errorf("failed to stop api dump process, pod name: %s, error: %v", podName, err)
	}
}

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
		printer.Errorf("Project ID is missing, set it using the environment variable %s, pod name: %s", POSTMAN_INSIGHTS_PROJECT_ID, pod.Name)
		return PodArgs{}, requiredEnvVarMissingErr
	}

	if insightsAPIKey == "" {
		printer.Errorf("API key is missing, set it using the environment variable %s, pod name: %s", POSTMAN_INSIGHTS_API_KEY, pod.Name)
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
	}

	return args, nil
}
