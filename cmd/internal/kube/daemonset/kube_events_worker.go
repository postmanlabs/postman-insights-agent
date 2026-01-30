package daemonset

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/go-utils/maps"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/deployment"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/spf13/viper"
	coreV1 "k8s.io/api/core/v1"
)

type baseEnvVarsError struct {
	podName      string
	missingAttrs []string
}

type allRequiredEnvVarsAbsentError struct {
	baseEnvVarsError
}

func (e *allRequiredEnvVarsAbsentError) Error() string {
	errMsg := fmt.Sprintf("All required environment variables are absent. "+
		"PodName: %s Missing env vars: %v\n", e.podName, e.missingAttrs)
	return errMsg
}

type requiredEnvVarMissingError struct {
	baseEnvVarsError
}

func (e *requiredEnvVarMissingError) Error() string {
	errMsg := fmt.Sprintf("One or more required environment variables are missing. "+
		"PodName: %s Missing env vars: %v\n", e.podName, e.missingAttrs)
	return errMsg
}

type requiredContainerConfig struct {
	projectID   string
	apiKey      string
	workspaceID string
	systemEnv   string
}

type containerConfig struct {
	requiredContainerConfig requiredContainerConfig
	disableReproMode        string
	dropNginxTraffic        string
	agentRateLimit          string
	alwaysCapturePayloads   string
}

// containerValidationResult holds the result of validating a container's required config.
// Used to pick the "best" container in a pod (most valid attrs) and to report errors.
type containerValidationResult struct {
	ValidAttrCount   int      // number of valid required attributes (for selection)
	MissingAttrs     []string // env var names that are required but missing
	ValidationErrors []string // e.g. "X must be a valid UUID"
}

func (r containerValidationResult) hasValidationErrors() bool {
	return len(r.ValidationErrors) > 0
}

func (r containerValidationResult) hasMissingAttrs() bool {
	return len(r.MissingAttrs) > 0
}

func (r containerValidationResult) hasNoAttrsSet() bool {
	return r.ValidAttrCount == 0
}

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

	err = d.SignalApiDumpProcessToStop(pod.UID, errors.Errorf("got pod delete event, pod: %s", podArgs.PodName))
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
			switch e := err.(type) {
			case *allRequiredEnvVarsAbsentError:
				printer.Debugf(e.Error())
			case *requiredEnvVarMissingError:
				printer.Errorf(e.Error())
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
	// Get the UUIDs of all containers in the pod
	containerUUIDs, err := d.KubeClient.GetContainerUUIDs(pod)
	if err != nil {
		return errors.Wrapf(err, "failed to get container UUIDs for pod: %s", pod.Name)
	}

	if len(containerUUIDs) == 0 {
		return errors.New("no running containers found in the pod")
	}

	containerConfigMap := maps.NewMap[string, containerConfig]()

	// Iterate over all containers in the pod to check for the required environment variables
	for _, containerUUID := range containerUUIDs {
		envVars, err := d.CRIClient.GetEnvVars(containerUUID)
		if err != nil {
			printer.Debugf("Failed to get environment variables for pod/container : %s/%s\n", pod.Name, containerUUID)
			continue
		}

		containerEnvVars := containerConfig{
			requiredContainerConfig: requiredContainerConfig{},
		}
		if projectID, exists := envVars[POSTMAN_INSIGHTS_PROJECT_ID]; exists {
			containerEnvVars.requiredContainerConfig.projectID = projectID
		}
		if apiKey, exists := envVars[POSTMAN_INSIGHTS_API_KEY]; exists {
			containerEnvVars.requiredContainerConfig.apiKey = apiKey
		}
		if workspaceID, exists := envVars[POSTMAN_INSIGHTS_WORKSPACE_ID]; exists {
			containerEnvVars.requiredContainerConfig.workspaceID = workspaceID
		}
		if systemEnv, exists := envVars[POSTMAN_INSIGHTS_SYSTEM_ENV]; exists {
			containerEnvVars.requiredContainerConfig.systemEnv = systemEnv
		}
		if disableReproMode, exists := envVars[POSTMAN_INSIGHTS_DISABLE_REPRO_MODE]; exists {
			containerEnvVars.disableReproMode = disableReproMode
		}
		if dropNginxTraffic, exists := envVars[POSTMAN_INSIGHTS_DROP_NGINX_TRAFFIC]; exists {
			containerEnvVars.dropNginxTraffic = dropNginxTraffic
		}
		if agentRateLimit, exists := envVars[POSTMAN_INSIGHTS_AGENT_RATE_LIMIT]; exists {
			containerEnvVars.agentRateLimit = agentRateLimit
		}
		if alwaysCapturePayloads, exists := envVars[POSTMAN_INSIGHTS_ALWAYS_CAPTURE_PAYLOADS]; exists {
			containerEnvVars.alwaysCapturePayloads = alwaysCapturePayloads
		}
		containerConfigMap[containerUUID] = containerEnvVars
	}

	mainUUID, mainContainerConfig, validation := selectMainContainer(containerConfigMap)

	deployment.SetK8sTraceTags(pod, podArgs.TraceTags)
	podArgs.ContainerUUID = mainUUID

	if validation.hasValidationErrors() {
		return errors.Errorf("Invalid configuration for pod %s: %v", pod.Name, validation.ValidationErrors)
	}
	if validation.hasMissingAttrs() {
		if validation.hasNoAttrsSet() {
			return &allRequiredEnvVarsAbsentError{
				baseEnvVarsError: baseEnvVarsError{
					missingAttrs: validation.MissingAttrs,
					podName:      pod.Name,
				},
			}
		}
		return &requiredEnvVarMissingError{
			baseEnvVarsError: baseEnvVarsError{
				missingAttrs: validation.MissingAttrs,
				podName:      pod.Name,
			},
		}
	}

	req := mainContainerConfig.requiredContainerConfig

	if req.workspaceID != "" {
		// Workspace mode
		podArgs.WorkspaceID = req.workspaceID
		podArgs.SystemEnv = req.systemEnv
		podArgs.PodCreds = PodCreds{
			InsightsAPIKey:      req.apiKey,
			InsightsEnvironment: d.InsightsEnvironment,
		}
	} else {
		// Traditional mode
		if err = akid.ParseIDAs(req.projectID, &podArgs.InsightsProjectID); err != nil {
			return errors.Wrap(err, "failed to parse project ID")
		}
		podArgs.PodCreds = PodCreds{
			InsightsAPIKey:      req.apiKey,
			InsightsEnvironment: d.InsightsEnvironment,
		}
	}

	// Check if Nginx traffic should be dropped, with a default fallback to the DaemonSet config
	podArgs.DropNginxTraffic = parseBoolConfig(mainContainerConfig.dropNginxTraffic, "dropNginxTraffic", pod.Name, viper.GetBool("drop-nginx-traffic"))

	// Determine ReproMode flag for the apidump process
	podArgs.ReproMode = d.InsightsReproModeEnabled

	if !d.InsightsReproModeEnabled {
		printer.Infof("Repro mode is disabled at the DaemonSet level for pod: %s\n", pod.Name)
		return nil
	}

	// Check if ReproMode is explicitly disabled at the pod level
	podArgs.ReproMode = !parseBoolConfig(mainContainerConfig.disableReproMode, "disableReproMode", pod.Name, !d.InsightsReproModeEnabled)

	podArgs.AgentRateLimit = d.InsightsRateLimit
	if mainContainerConfig.agentRateLimit != "" {
		if limit, err := strconv.ParseFloat(mainContainerConfig.agentRateLimit, 64); err == nil {
			podArgs.AgentRateLimit = limit
		} else {
			printer.Stderr.Warningf(
				"POSTMAN_INSIGHTS_AGENT_RATE_LIMIT value: '%v' could not be parsed: %v, using default: '%v'\n",
				mainContainerConfig.agentRateLimit, err, apispec.DefaultRateLimit)
		}
	}
	if podArgs.AgentRateLimit <= 0.0 {
		podArgs.AgentRateLimit = apispec.DefaultRateLimit
	}

	podArgs.AlwaysCapturePayloads = parseSliceConfig(mainContainerConfig.alwaysCapturePayloads, "alwaysCapturePayloads", pod.Name)

	return nil
}

// parseBoolConfig parses a boolean configuration value, logs errors if parsing fails,
// and returns the parsed value along with a default fallback.
func parseBoolConfig(configValue, configName, podName string, defaultValue bool) bool {
	if configValue == "" {
		return defaultValue
	}

	parsedValue, err := strconv.ParseBool(configValue)
	if err != nil {
		printer.Errorf("Invalid value for %s in pod %s: %s. Error: %v. Defaulting to %v.\n", configName, podName, configValue, err, defaultValue)
		return defaultValue
	}

	printer.Infof("%s is set to %v for pod: %s\n", configName, parsedValue, podName)
	return parsedValue
}

// parseSliceConfig parses a slice configuration value, logs errors if parsing fails,
// and returns the parsed value. Here the configValue should be a JSON string.
func parseSliceConfig(configValue, configName, podName string) []string {
	if configValue == "" {
		return []string{}
	}

	var parsedValue []string
	if err := json.Unmarshal([]byte(configValue), &parsedValue); err != nil {
		printer.Errorf("Invalid value for %s in pod %s: %s. Error: %v. Skipping.\n", configName, podName, configValue, err)
		return []string{}
	}

	printer.Infof("%s is set to %v for pod: %s\n", configName, parsedValue, podName)
	return parsedValue
}

// selectMainContainer picks the container in the pod with the most valid required
// attributes (for deciding which container's config to use). Returns its UUID, config,
// and validation result.
func selectMainContainer(containerConfigMap map[string]containerConfig) (uuid string, config containerConfig, result containerValidationResult) {
	result.ValidAttrCount = -1
	for u, cfg := range containerConfigMap {
		v := validateContainerConfig(cfg.requiredContainerConfig)
		if v.ValidAttrCount > result.ValidAttrCount {
			uuid = u
			config = cfg
			result = v
		}
	}
	return uuid, config, result
}

// validateContainerConfig validates a container's required config.
// - ValidAttrCount: used to pick the "best" container (higher = more complete config).
// - MissingAttrs: required env var names that are not set.
// - ValidationErrors: format errors (e.g. invalid UUID).
// Rules: apiKey is always required. Either (projectID for traditional mode) or
// (workspaceID + systemEnv as valid UUIDs for workspace mode) must be present.
func validateContainerConfig(cfg requiredContainerConfig) containerValidationResult {
	var r containerValidationResult

	// API key is required in both modes
	if cfg.apiKey != "" {
		r.ValidAttrCount++
	} else {
		r.MissingAttrs = append(r.MissingAttrs, POSTMAN_INSIGHTS_API_KEY)
	}

	isWorkspaceMode := cfg.workspaceID != "" || cfg.systemEnv != ""

	if isWorkspaceMode {
		// Workspace mode: workspaceID and systemEnv required, both must be valid UUIDs
		if cfg.workspaceID == "" {
			r.MissingAttrs = append(r.MissingAttrs, POSTMAN_INSIGHTS_WORKSPACE_ID)
		} else if _, err := uuid.Parse(cfg.workspaceID); err != nil {
			r.ValidationErrors = append(r.ValidationErrors, fmt.Sprintf("%s must be a valid UUID", POSTMAN_INSIGHTS_WORKSPACE_ID))
		} else {
			r.ValidAttrCount++
		}
		if cfg.systemEnv == "" {
			r.MissingAttrs = append(r.MissingAttrs, POSTMAN_INSIGHTS_SYSTEM_ENV)
		} else if _, err := uuid.Parse(cfg.systemEnv); err != nil {
			r.ValidationErrors = append(r.ValidationErrors, fmt.Sprintf("%s must be a valid UUID", POSTMAN_INSIGHTS_SYSTEM_ENV))
		} else {
			r.ValidAttrCount++
		}
	} else {
		// Traditional mode: projectID required
		if cfg.projectID != "" {
			r.ValidAttrCount++
		} else {
			r.MissingAttrs = append(r.MissingAttrs, POSTMAN_INSIGHTS_PROJECT_ID)
		}
	}

	return r
}
