package daemonset

import (
	"fmt"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	coreV1 "k8s.io/api/core/v1"
)

const (
	allRequiredEnvVarsAbsentMsg    = "All required environment variables are absent."
	requiredEnvVarMissingMsgFormat = "One or more required environment variables are missing." +
		"Ensure all the necessary environment variables are set correctly via ConfigMaps or Secrets. EnvVar: %s"
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

	apidumpArgs, err := d.inspectPodForEnvVars(podsWithoutAgentSidecar[0])
	if err != nil {
		if err.Error() != allRequiredEnvVarsAbsentMsg {
			printer.Errorf("failed to inspect pod for env vars, pod name: %s, error: %v", podName, err)
		}
		return
	}

	err = d.StartApiDumpProcess(apidumpArgs)
	if err != nil {
		printer.Errorf("failed to start api dump process, pod name: %s, error: %v", podName, err)
	}
}

func (d *Daemonset) handlePodDeleteEvent(podName string) {
	// TODO (K8S-MNS): Add check where we are already listining from this pod or not
	// Added as a part of apidump wrapper PR changes
	err := d.StopApiDumpProcess(podName)
	if err != nil {
		printer.Errorf("failed to stop api dump process, pod name: %s, error: %v", podName, err)
	}
}

func (d *Daemonset) inspectPodForEnvVars(pod coreV1.Pod) (ApidumpArgs, error) {
	// Get the UUID of the main container in the pod
	containerUUID, err := d.KubeClient.GetMainContainerUUID(pod)
	if err != nil {
		return ApidumpArgs{}, errors.Wrapf(err, "failed to get main container UUID for pod: %s", pod.Name)
	}

	// Get the environment variables of the main container
	envVars, err := d.CRIClient.GetEnvVars(containerUUID)
	if err != nil {
		return ApidumpArgs{}, errors.Wrapf(err, "failed to get environment variables for pod/container : %s/%s", pod.Name, containerUUID)
	}

	var (
		insightsProjectID akid.ServiceID
		insightsAPIKey    string
	)

	// Extract the necessary environment variables
	for key, value := range envVars {
		if key == string(POSTMAN_INSIGHTS_PROJECT_ID) {
			err := akid.ParseIDAs(value, &insightsProjectID)
			if err != nil {
				return ApidumpArgs{}, errors.Wrap(err, "failed to parse project ID")
			}
		} else if key == string(POSTMAN_INSIGHTS_API_KEY) {
			insightsAPIKey = value
		}
	}

	if (insightsProjectID == akid.ServiceID{}) && insightsAPIKey == "" {
		return ApidumpArgs{}, errors.New(allRequiredEnvVarsAbsentMsg)
	}

	if (insightsProjectID == akid.ServiceID{}) {
		return ApidumpArgs{}, errors.New(fmt.Sprintf(requiredEnvVarMissingMsgFormat, POSTMAN_INSIGHTS_PROJECT_ID))
	}

	if insightsAPIKey == "" {
		return ApidumpArgs{}, errors.New(fmt.Sprintf(requiredEnvVarMissingMsgFormat, POSTMAN_INSIGHTS_API_KEY))
	}

	return ApidumpArgs{insightsProjectID, insightsAPIKey}, nil
}
