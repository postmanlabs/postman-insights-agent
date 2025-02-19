package daemonset

import (
	"runtime/debug"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/apidump"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"k8s.io/apimachinery/pkg/types"
)

// StartApiDumpProcess initiates the API dump process for a given pod identified by its UID.
// It retrieves the pod arguments, changes the pod's traffic monitoring state, and starts the API dump process in a separate goroutine.
// The goroutine handles errors and state changes, and ensures the process is stopped properly.
func (d *Daemonset) StartApiDumpProcess(podUID types.UID) error {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		return err
	}

	err = podArgs.changePodTrafficMonitorState(TrafficMonitoringStarted, PodDetected, PodInitialized)
	if err != nil {
		return errors.Wrapf(err, "failed to change pod state, pod name: %s, from: %s to: %s",
			podArgs.PodName, podArgs.PodTrafficMonitorState, TrafficMonitoringStarted)
	}

	go func() (funcErr error) {
		// defer function handle the error (if any) in the apidump process and change the pod state accordingly
		defer func() {
			nextState := TrafficMonitoringEnded

			if err := recover(); err != nil {
				printer.Errorf("Panic occurred in apidump process for pod %s, err: %v\n%v\n",
					podArgs.PodName, err, string(debug.Stack()))
				nextState = TrafficMonitoringFailed
			} else if funcErr != nil {
				printer.Errorf("Error occurred in apidump process for pod %s, err: %v\n", podArgs.PodName, funcErr)
				nextState = TrafficMonitoringFailed
			} else {
				printer.Infof("Apidump process ended for pod %s", podArgs.PodName)
			}

			err = podArgs.changePodTrafficMonitorState(nextState, TrafficMonitoringStarted)
			if err != nil {
				printer.Errorf("Failed to change pod state, pod name: %s, from: %s to: %s, error: %v\n",
					podArgs.PodName, podArgs.PodTrafficMonitorState, nextState, err)
				return
			}

			// It is possible that the apidump process is already stopped and the stopChannel is of no use
			// This is just a safety check
			err := d.StopApiDumpProcess(podUID, err)
			if err != nil {
				printer.Errorf("Failed to stop api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
			}
		}()

		networkNamespace, err := d.CRIClient.GetNetworkNamespace(podArgs.ContainerUUID)
		if err != nil {
			funcErr = errors.Errorf("Failed to get network namespace for pod/containerUUID: %s/%s, err: %v",
				podArgs.PodName, podArgs.ContainerUUID, err)
			return
		}
		// Prepend '/host' to network namespace, since '/proc' folder is mounted to '/host/proc'
		networkNamespace = "/host" + networkNamespace

		apidumpArgs := apidump.Args{
			ClientID:                telemetry.GetClientID(),
			Domain:                  rest.Domain,
			ServiceID:               podArgs.InsightsProjectID,
			SampleRate:              apispec.DefaultSampleRate,
			WitnessesPerMinute:      apispec.DefaultRateLimit,
			LearnSessionLifetime:    apispec.DefaultTraceRotateInterval,
			TelemetryInterval:       apispec.DefaultTelemetryInterval_seconds,
			ProcFSPollingInterval:   apispec.DefaultProcFSPollingInterval_seconds,
			CollectTCPAndTLSReports: apispec.DefaultCollectTCPAndTLSReports,
			ParseTLSHandshakes:      apispec.DefaultParseTLSHandshakes,
			MaxWitnessSize_bytes:    apispec.DefaultMaxWitnessSize_bytes,
			ReproMode:               d.InsightsReproModeEnabled,
			DaemonsetArgs: optionals.Some(apidump.DaemonsetArgs{
				TargetNetworkNamespaceOpt: networkNamespace,
				StopChan:                  podArgs.StopChan,
				APIKey:                    podArgs.PodCreds.InsightsAPIKey,
				Environment:               podArgs.PodCreds.InsightsEnvironment,
			}),
		}

		if err := apidump.Run(apidumpArgs); err != nil {
			funcErr = errors.Wrapf(err, "Failed to run apidump process for pod %s", podArgs.PodName)
		}
		return
	}()

	return nil
}

// StopApiDumpProcess stops the API dump process for a given pod identified by its UID.
// It retrieves the pod arguments from a map and changes the pod's traffic monitor state.
// If successful, it sends a stop signal through the pod's stop channel.
func (d *Daemonset) StopApiDumpProcess(podUID types.UID, stopErr error) error {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		return err
	}

	err = podArgs.changePodTrafficMonitorState(TrafficMonitoringStopped,
		PodTerminated, DaemonSetShutdown, TrafficMonitoringFailed, TrafficMonitoringEnded)
	if err != nil {
		return errors.Wrapf(err, "failed to change pod state, pod name: %s, from: %s to: %s",
			podArgs.PodName, podArgs.PodTrafficMonitorState, TrafficMonitoringStopped)
	}

	printer.Infof("Stopping API dump process for pod %s\n", podArgs.PodName)
	podArgs.StopChan <- stopErr

	return nil
}
