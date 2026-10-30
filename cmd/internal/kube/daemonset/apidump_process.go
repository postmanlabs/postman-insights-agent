package daemonset

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/apidump"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"k8s.io/apimachinery/pkg/types"
)

// ingestCooldownKey returns the cooldown key and coverage reason for the pod's
// onboarding path; ok is false when the path has no cooldown.
func ingestCooldownKey(podArgs *PodArgs) (key, reason string, ok bool) {
	switch {
	case podArgs == nil:
		return "", "", false
	case podArgs.WorkspaceID != "":
		return rest.WorkspaceCooldownKey(podArgs.WorkspaceID, podArgs.SystemEnv), "workspace_not_linked", true
	case podArgs.DiscoveryMode:
		return rest.DiscoveryCooldownKey(podArgs.ClusterName, podArgs.Namespace, podArgs.WorkloadName), "discovery_ttl_cooldown", true
	}
	return "", "", false
}

// isIngestCooldownActive reports whether the backend recently refused
// ingestion for this pod's workspace or discovered workload.
func (d *Daemonset) isIngestCooldownActive(podArgs *PodArgs) bool {
	key, _, ok := ingestCooldownKey(podArgs)
	return ok && rest.IngestCooldown.ShouldSkip(key)
}

// StartApiDumpProcess initiates the API dump process for a given pod identified by its UID.
// It retrieves the pod arguments, changes the pod's traffic monitoring state, and starts the API dump process in a separate goroutine.
// The goroutine handles errors and state changes, and ensures the process is stopped properly.
func (d *Daemonset) StartApiDumpProcess(podUID types.UID) error {
	podArgs, err := d.getPodArgsFromMap(podUID)
	if err != nil {
		return err
	}

	// Cooldown is gated here (DaemonSet), not inside apidump: only the DaemonSet
	// sees every pod of a workload and can skip starting capture entirely.
	// Terminalize coverage before pruning so a later pod delete (when the UID
	// is no longer in PodArgsByNameMap) cannot leave a non-terminal coverage target.
	if d.isIngestCooldownActive(podArgs) {
		key, reason, _ := ingestCooldownKey(podArgs)
		until := "the cooldown elapses"
		if next, ok := rest.IngestCooldown.NextCheckAt(key); ok {
			until = next.Format(time.RFC3339)
		}
		printer.Infof(
			"Skipping apidump for pod %s; %s cooldown active until %s\n",
			podArgs.PodName, reason, until,
		)
		d.observeCoverageByUID(string(podUID), CoveragePodStopped, reason)
		if err := podArgs.changePodTrafficMonitorState(TrafficMonitoringEnded, PodRunning); err != nil {
			return errors.Wrapf(err, "failed to mark pod %s ended during %s cooldown", podArgs.PodName, reason)
		}
		return nil
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

			if nextState == TrafficMonitoringFailed {
				// The pod itself may still be running -- this is the capture
				// process failing underneath it, not a Kubernetes-reported
				// deletion or pod failure. See CoveragePodFailed.
				d.observeCoverageByUID(string(podUID), CoveragePodFailed, "apidump_process_failed")
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

		// Resolve the container's network-namespace inode, which HTTPS capture
		// is confined to. Without it buildHTTPSArgs turns HTTPS capture off for
		// the pod; HTTP/pcap capture is unaffected. A stop of the pod's capture
		// during the lookup (the pod deleted, the DaemonSet shutting down) ends
		// it before capture starts.
		var netnsInode uint64
		if d.EnableHTTPSCapture {
			lookupCtx, cancelLookup := context.WithTimeout(context.Background(), netnsLookupTimeout)
			inode, err := containerNetnsInode(lookupCtx, podArgs.StopChan, d.CRIClient.GetContainerPID, readNetnsInode,
				podArgs.ContainerUUID, netnsLookupInterval)
			cancelLookup()
			var stopped netnsLookupStopped
			switch {
			case errors.As(err, &stopped):
				printer.Infof("Received external stop signal for pod %s before capture started, error: %v\n", podArgs.PodName, stopped.stopErr)
				return nil
			case err != nil:
				printer.Warningf("ebpf: could not read the network namespace of pod %s within %s: %v\n", podArgs.PodName, netnsLookupTimeout, err)
			default:
				netnsInode = inode
			}
		}

		// Capture-liveness handle for this target. Written by the capture path via
		// atomics and read by the coverage tracker when it builds a snapshot.
		activity := &TargetActivity{}
		d.Coverage.AttachActivity(string(podUID), activity)

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
				ReportTelemetryCount:      func(event string, count uint64) { d.recordTelemetryCount(string(podUID), event, count) },
				SetFailureCategory:        func(category string) { d.Coverage.SetDiagnostics(string(podUID), category, nil, nil) },
				SetResolvedService: func(serviceID, serviceName string) {
					d.Coverage.SetResolvedService(string(podUID), serviceID, serviceName)
				},
				SetTrackingUser:   func(userID, teamID string) { d.Coverage.SetTrackingUser(string(podUID), userID, teamID) },
				SetCaptureMode:    func(mode string) { d.Coverage.SetCaptureMode(string(podUID), mode) },
				RecordPcapMessage: activity.RecordPcapMessage,
				RecordEBPFMessage: activity.RecordEBPFMessage,
				UploadReporter:    targetUploadReporter{coverage: d.Coverage, podUID: string(podUID)},
			}),
		}

		if err := apidump.Run(apidumpArgs); err != nil {
			// Intentional skip: end monitoring cleanly and terminalize coverage
			// so pruning cannot leak a target.
			if rest.IsIngestDisabledError(err) {
				_, reason, _ := ingestCooldownKey(podArgs)
				d.observeCoverageByUID(string(podUID), CoveragePodStopped, reason)
				return nil
			}
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
// The pod is captured only in its own network namespace (ContainerNetnsInode),
// from the node's libraries. When that namespace is not the pod's alone
// (ebpf.PodNetnsSkipReason: unknown, or the node's for a hostNetwork pod),
// HTTPS capture is off for the pod, so pcap keeps the TLS port: capturing
// anyway would upload other pods' and the node's traffic as this pod's.
func buildHTTPSArgs(d *Daemonset, podArgs *PodArgs, netnsInode uint64) apidump.HTTPSCaptureArgs {
	if !d.EnableHTTPSCapture {
		return apidump.HTTPSCaptureArgs{Enabled: false}
	}

	// DaemonSet HTTPS capture requires the shared node-scoped NodeCollector.
	// If initialisation failed at startup, do not fall back to per-pod
	// ebpf.Collect() — that would reload BPF programs once per monitored pod.
	if d.EBPFNodeCollector == nil {
		return apidump.HTTPSCaptureArgs{Enabled: false}
	}

	if reason := ebpf.PodNetnsSkipReason(netnsInode, d.httpsHostNetns); reason != "" {
		printer.Warningf("HTTPS capture is off for pod %s: %s, so its processes cannot be told from other pods' and the node's\n",
			podArgs.PodName, reason)
		return apidump.HTTPSCaptureArgs{Enabled: false}
	}

	return apidump.HTTPSCaptureArgs{
		Enabled:             true,
		ContainerNetnsInode: netnsInode,
		RateCapPerSec:       d.HTTPSRateCapPerSec,
		BodySizeCap:         d.HTTPSBodySizeCap,
		CBPFExcludePort:     d.HTTPSCBPFExcludePort,
		DisableThermostat:   d.HTTPSNoThermostat,
		Libraries:           d.HTTPSLibraries,
		NodeCollector:       d.EBPFNodeCollector,
	}
}

// The container of a pod the DaemonSet has just seen may not have started
// yet, and the runtime then reports no PID for it: the lookup tries every
// netnsLookupInterval for up to netnsLookupTimeout in all, runtime calls
// included.
const (
	netnsLookupTimeout  = 30 * time.Second
	netnsLookupInterval = time.Second
)

// netnsLookupStopped is the error of a containerNetnsInode that the pod's stop
// channel ended, with the error the stop carried.
type netnsLookupStopped struct{ stopErr error }

func (e netnsLookupStopped) Error() string {
	return fmt.Sprintf("stopped while looking up the network namespace: %v", e.stopErr)
}

// containerNetnsInode returns the network-namespace inode of the container,
// trying again while its PID or namespace cannot be read yet, until ctx is
// done, which also ends a runtime call in progress. A stop received from stop
// ends it with netnsLookupStopped, also one that came during a try that
// succeeded, so that a pod stopped during the lookup starts no capture.
func containerNetnsInode(ctx context.Context, stop <-chan error,
	containerPID func(ctx context.Context, containerID string) (int, error), netnsInode func(pid int) (uint64, error),
	containerID string, interval time.Duration) (uint64, error) {
	for {
		pid, err := containerPID(ctx, containerID)
		var inode uint64
		if err == nil {
			inode, err = netnsInode(pid)
		}
		select {
		case stopErr := <-stop:
			return 0, netnsLookupStopped{stopErr: stopErr}
		default:
		}
		if err == nil {
			return inode, nil
		}
		select {
		case stopErr := <-stop:
			return 0, netnsLookupStopped{stopErr: stopErr}
		case <-ctx.Done():
			return 0, err
		case <-time.After(interval):
		}
	}
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
