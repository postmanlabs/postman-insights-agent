package daemonset

import (
	"time"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (d *Daemonset) checkPodsHealth() {
	printer.Debugf("Checking pods health, time: %s", time.Now().UTC())

	var podUIDs []types.UID
	d.PodArgsByNameMap.Range(func(k, _ interface{}) bool {
		podUIDs = append(podUIDs, k.(types.UID))
		return true
	})

	podStatuses, err := d.KubeClient.GetPodsStatusByUIDs(podUIDs)
	if err != nil {
		printer.Errorf("Failed to get pods status: %v", err)
		return
	}

	for podUID, podStatus := range podStatuses {
		if podStatus == coreV1.PodSucceeded || podStatus == coreV1.PodFailed {
			printer.Infof("Pod %s has stopped running", podStatus)

			podArgs, err := d.getPodArgsFromMap(podUID)
			if err != nil {
				printer.Errorf("Failed to get podArgs for podUID %s: %v", podUID, err)
				continue
			}

			err = podArgs.changePodTrafficMonitorState(PodTerminated, TrafficMonitoringStarted)
			if err != nil {
				printer.Errorf("Failed to change pod state, pod name: %s, from: %d to: %d, error: %v",
					podArgs.PodName, podArgs.PodTrafficMonitorState, PodTerminated, err)
				continue
			}

			err = d.StopApiDumpProcess(podUID, errors.Errorf("pod %s has stopped running, status: %s", podArgs.PodName, podStatus))
			if err != nil {
				printer.Errorf("Failed to stop api dump process, pod name: %s, error: %v", podArgs.PodName, err)
			}
		}
	}
}

// pruneStoppedProcesses removes the stopped processes from the map
// In first iteration, it changes the state of the pod to RemovePodFromMap
// In second iteration, it removes the pod from the map
func (d *Daemonset) pruneStoppedProcesses() {
	printer.Debugf("Pruning stopped processes, time: %s", time.Now().UTC())

	d.PodArgsByNameMap.Range(func(k, v interface{}) bool {
		podUID := k.(types.UID)
		podArgs := v.(*PodArgs)

		switch podArgs.PodTrafficMonitorState {
		case TrafficMonitoringStopped:
			err := podArgs.changePodTrafficMonitorState(RemovePodFromMap, TrafficMonitoringStopped)
			if err != nil {
				printer.Errorf("Failed to change pod state, pod name: %s, from: %d to: %d",
					podArgs.PodName, podArgs.PodTrafficMonitorState, RemovePodFromMap)
			}
		case RemovePodFromMap:
			d.PodArgsByNameMap.Delete(podUID)
		}
		return true
	})
}
