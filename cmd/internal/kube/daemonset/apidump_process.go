package daemonset

import (
	"fmt"
	"os"
	"runtime/debug"
	"syscall"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/apidump"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
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

		// Resolve the container's network-namespace inode for pod-level eBPF
		// scoping. Failures are non-fatal: we fall back to namespace-level
		// filtering (TargetNamespaces) inside buildHTTPSArgs, which is less
		// precise but still correct. HTTP/pcap capture is unaffected.
		var netnsInode uint64
		if d.EnableHTTPSCapture {
			containerPID, err := d.CRIClient.GetContainerPID(podArgs.ContainerUUID)
			if err != nil {
				printer.Warningf(
					"ebpf: could not get container PID for pod %s (falling back to namespace-level eBPF scoping): %v\n",
					podArgs.PodName, err)
			} else {
				inode, err := readNetnsInode(containerPID)
				if err != nil {
					printer.Warningf(
						"ebpf: could not read netns inode for pod %s PID %d (falling back to namespace-level eBPF scoping): %v\n",
						podArgs.PodName, containerPID, err)
				} else {
					netnsInode = inode
				}
			}
		}

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
			Namespace:               podArgs.Namespace,
			WorkloadName:            podArgs.WorkloadName,
			WorkloadType:            podArgs.WorkloadType,
			Labels:                  podArgs.Labels,
			HTTPS:                   buildHTTPSArgs(d, podArgs, netnsInode),
			DaemonsetArgs: optionals.Some(apidump.DaemonsetArgs{
				TargetNetworkNamespaceOpt: networkNamespace,
				StopChan:                  podArgs.StopChan,
				APIKey:                    podArgs.PodCreds.InsightsAPIKey,
				Environment:               podArgs.PodCreds.InsightsEnvironment,
				TraceTags:                 podArgs.TraceTags,
			}),
		}

		if err := apidump.Run(apidumpArgs); err != nil {
			funcErr = errors.Wrapf(err, "failed to run apidump process for pod %s", podArgs.PodName)
		}
		return funcErr
	}()

	return nil
}

// buildHTTPSArgs constructs the apidump.HTTPSCaptureArgs for a per-pod
// apidump.Run() call from the DaemonSet-level HTTPS config, the pod metadata,
// and the container's network-namespace inode.
//
// Scoping priority (most precise wins):
//  1. ContainerNetnsInode — pod-level, derived from the container init PID.
//     Restricts eBPF discovery to exactly the processes inside this pod's
//     netns. Eliminates duplicate captures when a namespace has N replicas.
//  2. TargetNamespaces — namespace-level fallback used when the inode lookup
//     fails (CRI unavailable, container not yet started, etc.) and the pod
//     namespace is known (discovery mode). Causes N× capture for N replicas;
//     acceptable only as a degraded fallback.
//  3. No filter — when HTTPS is disabled or neither of the above is available.
func buildHTTPSArgs(d *Daemonset, podArgs *PodArgs, netnsInode uint64) apidump.HTTPSCaptureArgs {
	if !d.EnableHTTPSCapture {
		return apidump.HTTPSCaptureArgs{Enabled: false}
	}

	args := apidump.HTTPSCaptureArgs{
		Enabled:             true,
		ContainerNetnsInode: netnsInode,
		RateCapPerSec:       d.HTTPSRateCapPerSec,
		BodySizeCap:         d.HTTPSBodySizeCap,
		CBPFExcludePort:     d.HTTPSCBPFExcludePort,
		DisableThermostat:   d.HTTPSNoThermostat,
		EnableJavaTLS:       d.EnableJavaTLS,
	}

	// Only fall back to namespace-level filtering when the inode is
	// unavailable. Prefer the inode path: it is pod-level and avoids N×
	// duplicate captures for scaled deployments.
	if netnsInode == 0 && podArgs.Namespace != "" {
		args.TargetNamespaces = []string{podArgs.Namespace}
	}

	return args
}

// readNetnsInode returns the network-namespace inode for the given PID by
// stat-ing /proc/<pid>/ns/net (or /host/proc/<pid>/ns/net when the DaemonSet
// bind-mounts the root /proc there). Returns 0 and a non-nil error if the
// inode cannot be determined.
func readNetnsInode(pid int) (uint64, error) {
	// On a DaemonSet the agent's /host/proc is the node's root /proc, which
	// is where BPF-emitted root-namespace PIDs live. Fall back to /proc when
	// /host/proc/self is absent (running outside a DaemonSet).
	procRoot := "/proc"
	if _, err := os.Stat("/host/proc/self"); err == nil {
		procRoot = "/host/proc"
	}
	path := fmt.Sprintf("%s/%d/ns/net", procRoot, pid)
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("readNetnsInode: stat %s: %w", path, err)
	}
	return st.Ino, nil
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
