package daemonset

import (
	"time"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// checkPodsHealth checks the health status of pods managed by the Daemonset.
// It retrieves the current status of each pod and performs actions based on their status.
// If a pod has stopped running (either succeeded or failed) or not exists anymore, it updates the pod's traffic monitor state
// and stops the API dump process for that pod.
// If a pod is running and it's traffic is not monitored, it starts the API dump process for that pod.
func (d *Daemonset) checkPodsHealth() {
	printer.Debugf("Checking pods health, time: %s\n", time.Now().UTC())

	var podUIDs []types.UID
	d.PodArgsByNameMap.Range(func(k, _ interface{}) bool {
		podUIDs = append(podUIDs, k.(types.UID))
		return true
	})

	// Get all pods in the node where the agent is running
	pods, err := d.KubeClient.GetPodsInAgentNode()
	if err != nil {
		printer.Errorf("failed to get pods in node: %v\n", err)
	}
	// Filter out pods that do not have the agent sidecar container
	podsWithoutAgentSidecar, err := d.KubeClient.FilterPodsByContainerImage(pods, agentImage, true)
	if err != nil {
		printer.Errorf("failed to filter pods by container image: %v\n", err)
	}
	// Detect unmonitored pods
	for _, pod := range podsWithoutAgentSidecar {
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

		if _, ok := d.PodArgsByNameMap.Load(pod.UID); !ok {
			err = d.addPodArgsToMap(pod.UID, args, PodRunning)
			if err != nil {
				printer.Errorf("Failed to add pod args to map, pod name: %s, error: %v\n", pod.Name, err)
				continue
			}
			podUIDs = append(podUIDs, pod.UID)
		}
	}

	if len(podUIDs) == 0 {
		printer.Debugf("No pods to check health\n")
		return
	}

	podStatuses, err := d.KubeClient.GetPodsStatusByUIDs(podUIDs)
	if err != nil {
		printer.Errorf("Failed to get pods status: %v\n", err)
	}

	for _, podUID := range podUIDs {
		podStatus, ok := podStatuses[podUID]
		if !ok {
			printer.Infof("Pod status not found for podUID %s, Pod doesn't exists anymore\n", podUID)
			d.handleTerminatedPod(podUID, errors.Errorf("pod %s doesn't exists anymore", podUID), true)
		}

		switch podStatus {
		case coreV1.PodSucceeded, coreV1.PodFailed:
			printer.Infof("Pod with UID %s has stopped running, status: %s\n", podUID, podStatus)
			d.handleTerminatedPod(podUID, errors.Errorf("pod %s has stopped running, status: %s", podUID, podStatus), false)
		case coreV1.PodRunning:
			printer.Debugf("Pod with UID %s, status:%s\n", podUID, podStatus)
			d.handleUnmonitoredPod(podUID)
		}
	}
}

// handleTerminatedPod handles the terminated pod by changing the pod's traffic monitor state to PodTerminated
// and stopping the API dump process for that pod.
func (d *Daemonset) handleTerminatedPod(podUID types.UID, podStatusErr error, podDoesNotExists bool) {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		printer.Infof("Failed to get podArgs for podUID %s: %v\n", podUID, err)
		return
	}

	// If pod doesn't exists anymore, we don't need to check the pod status
	// We can directly change the state to PodTerminated
	if podDoesNotExists {
		err = podArgs.changePodTrafficMonitorState(PodTerminated)
	} else {
		err = podArgs.changePodTrafficMonitorState(PodTerminated, TrafficMonitoringRunning)
	}
	if err != nil {
		printer.Infof("Failed to change pod state, pod name: %s, from: %s to: %s, error: %v\n",
			podArgs.PodName, podArgs.PodTrafficMonitorState, PodTerminated, err)
		return
	}

	err = d.SignalApiDumpProcessToStop(podUID, podStatusErr)
	if err != nil {
		printer.Errorf("Failed to stop api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
	}
}

// handleUnmonitoredPod starts the API dump process for the pod if it is not already started.
// If pod's monitoring state is still in PodRunning, it means there is a bug.
// The program should have started the API dump process if it is stored in the map.
func (d *Daemonset) handleUnmonitoredPod(podUID types.UID) {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		printer.Infof("Failed to get podArgs for podUID %s: %v\n", podUID, err)
		return
	}

	if podArgs.PodTrafficMonitorState == PodRunning {
		printer.Debugf("Apidump process not started for pod %s during its initialization, starting now\n", podArgs.PodName)
		err = d.StartApiDumpProcess(podUID)
		if err != nil {
			printer.Errorf("Failed to start api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
		}
	}
}

// pruneStoppedProcesses removes the stopped processes from the map
// In first iteration, it changes the state of the pod to RemovePodFromMap
// In second iteration, it removes the pod from the map
func (d *Daemonset) pruneStoppedProcesses() {
	printer.Debugf("Pruning stopped processes, time: %s\n", time.Now().UTC())

	d.PodArgsByNameMap.Range(func(k, v interface{}) bool {
		podUID := k.(types.UID)
		podArgs := v.(*PodArgs)

		switch podArgs.PodTrafficMonitorState {
		case TrafficMonitoringEnded, TrafficMonitoringFailed:
			err := podArgs.markAsPruneReady()
			if err != nil {
				printer.Errorf("Failed to mark pod %s as prune ready, error: %v\n", podArgs.PodName, err)
			}
		case RemovePodFromMap:
			// Close the stop channel before removing the pod from the map
			close(podArgs.StopChan)
			d.PodArgsByNameMap.Delete(podUID)
		}
		return true
	})
}
