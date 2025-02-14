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
// If a pod has stopped running (either succeeded or failed), it updates the pod's traffic monitor state
// and stops the API dump process for that pod.
func (d *Daemonset) checkPodsHealth() {
	printer.Debugf("Checking pods health, time: %s\n", time.Now().UTC())

	var podUIDs []types.UID
	d.PodArgsByNameMap.Range(func(k, _ interface{}) bool {
		podUIDs = append(podUIDs, k.(types.UID))
		return true
	})

	podStatuses, err := d.KubeClient.GetPodsStatusByUIDs(podUIDs)
	if err != nil {
		printer.Errorf("Failed to get pods status: %v\n", err)
		return
	}

	for podUID, podStatus := range podStatuses {
		switch podStatus {
		case coreV1.PodSucceeded, coreV1.PodFailed:
			printer.Infof("Pod %s has stopped running\n", podStatus)

			podArgs, err := d.getPodArgsFromMap(podUID)
			if err != nil {
				printer.Infof("Failed to get podArgs for podUID %s: %v\n", podUID, err)
				continue
			}

			err = podArgs.changePodTrafficMonitorState(PodTerminated, TrafficMonitoringStarted)
			if err != nil {
				printer.Infof("Failed to change pod state, pod name: %s, from: %s to: %s, error: %v\n",
					podArgs.PodName, podArgs.PodTrafficMonitorState, PodTerminated, err)
				continue
			}

			err = d.StopApiDumpProcess(podUID, errors.Errorf("pod %s has stopped running, status: %s", podArgs.PodName, podStatus))
			if err != nil {
				printer.Errorf("Failed to stop api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
			}
		case coreV1.PodRunning:
			printer.Debugf("Pod %s is running\n", podStatus)

			podArgs, err := d.getPodArgsFromMap(podUID)
			if err != nil {
				printer.Infof("Failed to get podArgs for podUID %s: %v\n", podUID, err)
				continue
			}

			// If pod's monitoring state is still in PodDetected or PodInitialized, it means there is a bug.
			// The program should have started the API dump process if it is stored in the map.
			if podArgs.PodTrafficMonitorState == PodDetected || podArgs.PodTrafficMonitorState == PodInitialized {
				printer.Debugf("Apidump process not started for pod %s during it's initialization, starting now\n", podArgs.PodName)
				err = d.StartApiDumpProcess(podUID)
				if err != nil {
					printer.Errorf("Failed to start api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
				}
			}
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
		case TrafficMonitoringStopped:
			err := podArgs.changePodTrafficMonitorState(RemovePodFromMap, TrafficMonitoringStopped)
			if err != nil {
				printer.Errorf("Failed to change pod state, pod name: %s, from: %s to: %s\n",
					podArgs.PodName, podArgs.PodTrafficMonitorState, RemovePodFromMap)
			}
		case RemovePodFromMap:
			d.PodArgsByNameMap.Delete(podUID)
		}
		return true
	})
}
