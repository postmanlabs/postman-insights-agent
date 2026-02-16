package daemonset

import (
	"runtime/debug"
	"strings"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/apidump"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"k8s.io/apimachinery/pkg/types"
)

// splitServiceName splits a "namespace/workload-name" string into its parts.
func splitServiceName(serviceName string) [2]string {
	parts := strings.SplitN(serviceName, "/", 2)
	if len(parts) == 2 {
		return [2]string{parts[0], parts[1]}
	}
	return [2]string{"", serviceName}
}

// StartApiDumpProcess initiates the API dump process for a given pod identified by its UID.
// It retrieves the pod arguments, changes the pod's traffic monitoring state, and starts the API dump process in a separate goroutine.
// The goroutine handles errors and state changes, and ensures the process is stopped properly.
func (d *Daemonset) StartApiDumpProcess(podUID types.UID) error {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		return err
	}

	err = podArgs.changePodTrafficMonitorState(TrafficMonitoringRunning, PodRunning)
	if err != nil {
		return errors.Wrapf(err, "failed to change pod state, pod name: %s, from: %s to: %s",
			podArgs.PodName, podArgs.PodTrafficMonitorState, TrafficMonitoringRunning)
	}

	// Increment the wait group counter
	d.ApidumpProcessesWG.Add(1)

	go func() (funcErr error) {
		// defer function handle the error (if any) in the apidump process and change the pod state accordingly
		defer func() {
			// Decrement the wait group counter
			d.ApidumpProcessesWG.Done()

			nextState := TrafficMonitoringEnded

			if err := recover(); err != nil {
				printer.Errorf("Panic occurred in apidump process for pod %s, err: %v\n%v\n",
					podArgs.PodName, err, string(debug.Stack()))
				nextState = TrafficMonitoringFailed
			} else if funcErr != nil {
				printer.Errorf("Error occurred in apidump process for pod %s, err: %v\n", podArgs.PodName, funcErr)
				nextState = TrafficMonitoringFailed
			} else {
				printer.Infof("Apidump process ended for pod %s\n", podArgs.PodName)
			}

			// Move monitoring state to final apidump processing state
			err = podArgs.changePodTrafficMonitorState(nextState,
				TrafficMonitoringRunning, PodSucceeded, PodFailed, PodTerminated, DaemonSetShutdown)
			if err != nil {
				printer.Errorf("Failed to change pod state, pod name: %s, from: %s to: %s, error: %v\n",
					podArgs.PodName, podArgs.PodTrafficMonitorState, nextState, err)
			}
		}()

		networkNamespace, err := d.CRIClient.GetNetworkNamespace(podArgs.ContainerUUID)
		if err != nil {
			funcErr = errors.Errorf("Failed to get network namespace for pod/containerUUID: %s/%s, err: %v",
				podArgs.PodName, podArgs.ContainerUUID, err)
			return funcErr
		}
		// Prepend '/host' to network namespace, since '/proc' folder is mounted to '/host/proc'
		networkNamespace = "/host" + networkNamespace

		apidumpArgs := apidump.Args{
			ClientID:                akid.GenerateClientID(),
			Domain:                  rest.Domain,
			ServiceID:               podArgs.InsightsProjectID,
			SampleRate:              apispec.DefaultSampleRate,
			WitnessesPerMinute:      podArgs.AgentRateLimit,
			LearnSessionLifetime:    apispec.DefaultTraceRotateInterval,
			TelemetryInterval:       apispec.DefaultTelemetryInterval_seconds,
			ProcFSPollingInterval:   apispec.DefaultProcFSPollingInterval_seconds,
			CollectTCPAndTLSReports: apispec.DefaultCollectTCPAndTLSReports,
			ParseTLSHandshakes:      apispec.DefaultParseTLSHandshakes,
			MaxWitnessSize_bytes:    apispec.DefaultMaxWitnessSize_bytes,
			ReproMode:               podArgs.ReproMode,
			DropNginxTraffic:        podArgs.DropNginxTraffic,
			MaxWitnessUploadBuffers: apispec.DefaultMaxWintessUploadBuffers,
			AlwaysCapturePayloads:   podArgs.AlwaysCapturePayloads,
			WorkspaceID:             podArgs.WorkspaceID,
			SystemEnv:               podArgs.SystemEnv,
			DiscoveryMode:           podArgs.DiscoveryMode,
			ServiceName:             podArgs.DiscoveryServiceName,
			ClusterName:             podArgs.ClusterName,
			WorkloadName:            podArgs.WorkloadName,
			WorkloadType:            podArgs.WorkloadType,
			Labels:                  podArgs.Labels,
			DaemonsetArgs: optionals.Some(apidump.DaemonsetArgs{
				TargetNetworkNamespaceOpt: networkNamespace,
				StopChan:                  podArgs.StopChan,
				APIKey:                    podArgs.PodCreds.InsightsAPIKey,
				Environment:               podArgs.PodCreds.InsightsEnvironment,
				TraceTags:                 podArgs.TraceTags,
			}),
		}

		// In discovery mode, extract namespace and workload name from the service name.
		if podArgs.DiscoveryMode && podArgs.DiscoveryServiceName != "" {
			parts := splitServiceName(podArgs.DiscoveryServiceName)
			apidumpArgs.Namespace = parts[0]
			apidumpArgs.WorkloadName = parts[1]
		}

		if err := apidump.Run(apidumpArgs); err != nil {
			funcErr = errors.Wrapf(err, "failed to run apidump process for pod %s", podArgs.PodName)
		}
		return funcErr
	}()

	return nil
}

// SignalApiDumpProcessToStop signals the API dump process to stop for a given pod
// identified by its UID. It retrieves the process's stop channel object from a map
// and sends a stop signal to trigger apidump shutdown.
func (d *Daemonset) SignalApiDumpProcessToStop(podUID types.UID, stopErr error) error {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		return err
	}

	printer.Infof("Stopping API dump process for pod %s\n", podArgs.PodName)
	podArgs.StopChan <- stopErr

	return nil
}
