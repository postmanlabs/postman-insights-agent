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

func (d *Daemonset) handlePodAddEvent(podUID types.UID) {
	pods, err := d.KubeClient.GetPodsByUIDs([]types.UID{podUID})
	if err != nil {
		printer.Errorf("failed to get pod for k8s added event, podUID: %s, error: %v", podUID, err)
		return
	}
	if len(pods) == 0 {
		printer.Infof("no pod found for k8s added event, podUID: %s", podUID)
		return
	}
	if len(pods) > 1 {
		printer.Errorf("multiple pods found for single UID, this should not happen, podUID: %s", podUID)
		return
	}

	// Filter out pods that do not have the agent sidecar container
	podsWithoutAgentSidecar, err := d.KubeClient.FilterPodsByContainerImage(pods, agentImage, true)
	if err != nil {
		printer.Errorf("failed to filter pod by container image: %v", err)
		return
	}
	if len(podsWithoutAgentSidecar) == 0 {
		printer.Infof("pod already has agent sidecar container, skipping, podUID: %s", podUID)
		return
	}

	pod := podsWithoutAgentSidecar[0]

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
		return
	}

	// Set the pod stage to PodInitialized, store it in the map and start the apidump process
	args.setPodTrafficMonitorStage(PodInitialized)
	d.PodArgsByNameMap.Store(pod.UID, args)
	err = d.StartApiDumpProcess(pod.UID)
	if err != nil {
		printer.Errorf("failed to start api dump process, pod name: %s, error: %v", pod.Name, err)
	}
}

func (d *Daemonset) handlePodDeleteEvent(podUID types.UID) {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		printer.Errorf("failed to get podArgs for pod UID %s: %v", podUID, err)
		return
	}

	isSameStage, err := podArgs.validatePodTrafficMonitorStage(PodTerminated, TrafficMonitoringStarted)
	if err != nil {
		printer.Errorf("pod %s is in invalid state %d", podArgs.PodName, podArgs.PodTrafficMonitorStage)
	}
	if isSameStage {
		printer.Errorf("pod %s is already in state %d", podArgs.PodName, podArgs.PodTrafficMonitorStage)
	}

	podArgs.setPodTrafficMonitorStage(PodTerminated)

	err = d.StopApiDumpProcess(podUID, errors.Errorf("got pod delete event, pod: %s", podArgs.PodName))
	if err != nil {
		printer.Errorf("failed to stop api dump process, pod name: %s, error: %v", podArgs.PodName, err)
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
