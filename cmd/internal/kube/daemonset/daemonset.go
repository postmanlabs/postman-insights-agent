package daemonset

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/postmanlabs/postman-insights-agent/integrations/cri_apis"
	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/version"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/types"
)

const (
	apiContextTimeout = 20 * time.Second
	agentImage        = "public.ecr.aws/postman/postman-insights-agent:latest"
)

type DaemonsetArgs struct {
	ReproMode bool
	RateLimit float64

	// Discovery mode fields
	DiscoveryMode     bool
	IncludeNamespaces []string
	ExcludeNamespaces []string
	IncludeLabels     map[string]string
	ExcludeLabels     map[string]string

	// HTTPS capture via eBPF (uprobes on libssl).
	// When true, each per-pod apidump.Run() starts an eBPF HTTPS capture
	// pipeline alongside the pcap pipeline, scoped to the pod's namespace.
	EnableHTTPSCapture   bool
	HTTPSRateCapPerSec   uint32 // 0 = unlimited
	HTTPSBodySizeCap     uint32 // 0 = default (16384 bytes)
	HTTPSCBPFExcludePort uint16 // 0 = no cBPF port exclusion; kube run defaults to 443
	HTTPSNoThermostat    bool
}

type Daemonset struct {
	ClusterName              string
	InsightsEnvironment      string
	InsightsReproModeEnabled bool
	InsightsRateLimit        float64

	// InsightsUserID and InsightsTeamID are this agent's own Postman identity,
	// resolved once at startup from the DaemonSet-level API key and stamped on
	// every agent-scope telemetry event. They are the only tenancy the backend
	// records for those rows, so when they are empty (no DaemonSet-level API
	// key, or the lookup failed) agent lifecycle events are unattributed.
	// Per-pod counters carry their own target-scoped identity instead; see
	// CoverageTracker.TargetIdentity.
	InsightsUserID string
	InsightsTeamID string

	// HTTPS capture config, propagated from DaemonsetArgs.
	EnableHTTPSCapture   bool
	HTTPSRateCapPerSec   uint32
	HTTPSBodySizeCap     uint32
	HTTPSCBPFExcludePort uint16
	HTTPSNoThermostat    bool

	// EBPFNodeCollector is a node-scoped shared eBPF collector initialised once
	// per agent pod when EnableHTTPSCapture is true. Nil when HTTPS capture is
	// disabled, NodeCollector initialisation failed, or on non-Linux /
	// non-insights_bpf builds.
	EBPFNodeCollector *ebpf.NodeCollector

	KubeClient  kube_apis.KubeClient
	CRIClient   *cri_apis.CriClient
	FrontClient rest.FrontClient

	// Note: Only filtered pods are stored in this map, i.e., they have required env vars
	// and do not have the agent sidecar container
	PodArgsByNameMap sync.Map

	// WaitGroup to wait for all apidump processes to stop
	ApidumpProcessesWG sync.WaitGroup

	podEventDispatcher *podEventDispatcher

	PodHealthCheckInterval time.Duration
	TelemetryInterval      time.Duration

	// Discovery mode
	DiscoveryMode     bool
	InsightsAPIKey    string // DaemonSet-level API key for discovery mode
	PodFilter         *PodFilter
	Coverage          *CoverageTracker
	AgentID           string
	telemetrySequence uint64

	// telemetryEventsMu guards both the pending counters and the start of the
	// window they cover, so a flush cannot split the two.
	telemetryEventsMu    sync.Mutex
	telemetryEvents      map[string]map[string]uint64
	telemetryWindowStart time.Time

	// agent_state bookkeeping. Only ever touched from sendTelemetry, which
	// TelemetryWorker calls sequentially off a single ticker, so no lock is
	// needed.
	agentState          rest.AgentState
	agentStateSince     time.Time
	lastTelemetryFailed bool
}

// applyEnvVarDefaults reads discovery-mode environment variables and applies
// them as defaults. CLI flags (non-zero values) take precedence over env vars.
// The filtering env vars are only read when discovery mode is active (either
// via CLI flag or the POSTMAN_INSIGHTS_DISCOVERY_MODE env var).
func (a *DaemonsetArgs) applyEnvVarDefaults() {
	// POSTMAN_INSIGHTS_DISCOVERY_MODE
	if !a.DiscoveryMode {
		if v := os.Getenv(POSTMAN_INSIGHTS_DISCOVERY_MODE); strings.EqualFold(v, "true") {
			a.DiscoveryMode = true
		}
	}

	// The remaining env vars are only relevant when discovery mode is enabled.
	if !a.DiscoveryMode {
		return
	}

	// POSTMAN_INSIGHTS_INCLUDE_NAMESPACES (comma-separated)
	if len(a.IncludeNamespaces) == 0 {
		if v := os.Getenv(POSTMAN_INSIGHTS_INCLUDE_NAMESPACES); v != "" {
			a.IncludeNamespaces = splitAndTrim(v)
		}
	}

	// POSTMAN_INSIGHTS_EXCLUDE_NAMESPACES (comma-separated)
	if len(a.ExcludeNamespaces) == 0 {
		if v := os.Getenv(POSTMAN_INSIGHTS_EXCLUDE_NAMESPACES); v != "" {
			a.ExcludeNamespaces = splitAndTrim(v)
		}
	}

	// POSTMAN_INSIGHTS_INCLUDE_LABELS (comma-separated key=value pairs)
	if len(a.IncludeLabels) == 0 {
		if v := os.Getenv(POSTMAN_INSIGHTS_INCLUDE_LABELS); v != "" {
			a.IncludeLabels = parseKeyValuePairs(v)
		}
	}

	// POSTMAN_INSIGHTS_EXCLUDE_LABELS (comma-separated key=value pairs)
	if len(a.ExcludeLabels) == 0 {
		if v := os.Getenv(POSTMAN_INSIGHTS_EXCLUDE_LABELS); v != "" {
			a.ExcludeLabels = parseKeyValuePairs(v)
		}
	}

}

// splitAndTrim splits a comma-separated string and trims whitespace from each element.
// Empty elements are discarded.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// parseKeyValuePairs parses a comma-separated list of key=value pairs into a map.
// Entries without an '=' sign are skipped with a warning.
func parseKeyValuePairs(s string) map[string]string {
	pairs := splitAndTrim(s)
	result := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			printer.Warningf("Ignoring malformed label entry %q (expected key=value)\n", pair)
			continue
		}
		result[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return result
}

func StartDaemonset(args DaemonsetArgs) error {
	// Apply environment variable defaults before processing.
	args.applyEnvVarDefaults()

	// Check if the agent is running in a linux environment
	if runtime.GOOS != "linux" {
		return errors.New("This command is only supported on linux images")
	}

	// Initialize the front client
	postmanInsightsVerificationToken := os.Getenv(POSTMAN_INSIGHTS_VERIFICATION_TOKEN)
	telemetryDomain := os.Getenv(POSTMAN_INSIGHTS_TELEMETRY_DOMAIN)
	if telemetryDomain == "" {
		telemetryDomain = rest.Domain
	}
	frontClient := rest.NewFrontClient(
		telemetryDomain,
		telemetry.GetClientID(),
		rest.DaemonsetAuthHandler(postmanInsightsVerificationToken),
		nil,
	)
	if viper.GetBool("test_only_disable_telemetry_https") {
		frontClient.UseInsecureScheme()
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	// Resolve this agent's own Postman identity before the first telemetry
	// event, so agent_started carries it like every later agent-scope event.
	agentUserID, agentTeamID := resolveAgentIdentity(telemetryDomain)

	// Send initial telemetry
	clusterName := os.Getenv(POSTMAN_INSIGHTS_CLUSTER_NAME)
	agentID := akid.String(telemetry.GetClientID())
	coverage := NewCoverageTracker(agentID, 1000)
	if clusterName == "" && args.DiscoveryMode {
		return errors.New(
			"discovery mode requires a cluster name: set POSTMAN_INSIGHTS_CLUSTER_NAME env var",
		)
	}
	telemetryInterval := DefaultTelemetryInterval
	if viper.GetBool("test_only_disable_https") || viper.GetBool("test_only_disable_telemetry_https") {
		telemetryInterval = DevelopmentTelemetryInterval
	}
	// Single source of sequence numbers for this run, shared by the startup event
	// and every subsequent heartbeat and counter flush.
	var telemetrySequence uint64
	if clusterName == "" {
		printer.Infof(
			"The cluster name is missing. Telemetry will not be sent from this agent, " +
				"it will not be tracked on our end, and it will not appear in the app's " +
				"list of clusters where the agent is running.\n",
		)
		telemetryInterval = 0
	} else {
		// Send Initial telemetry. Sequence comes from the same counter the
		// heartbeat uses so the two cannot collide; no targets exist yet, so the
		// snapshot is deliberately omitted rather than sent as an empty array.
		err := frontClient.PostDaemonsetAgentTelemetry(ctx, rest.DaemonsetTelemetryRequest{
			Type:              rest.TelemetryTypeEvents,
			Event:             "agent_started",
			AgentID:           agentID,
			Sequence:          atomic.AddUint64(&telemetrySequence, 1),
			SchemaVersion:     "v1",
			KubernetesCluster: clusterName,
			UserID:            agentUserID,
			TeamID:            agentTeamID,
			AgentVersion:      version.ReleaseVersion().String(),
			GitVersion:        version.GitVersion(),
		})
		if err != nil {
			printer.Errorf("Failed to send initial daemonset agent telemetry: %v\n", err)
			printer.Infof(
				"Agent will try to send telemetry again, if the error still persists, agent " +
					"will not be tracked on our end, and it will not appear in the app's list of " +
					"clusters where the agent is running.\n",
			)
		}
	}

	kubeClient, err := kube_apis.NewKubeClient()
	if err != nil {
		sendAgentFailed(frontClient, agentID, clusterName, agentUserID, agentTeamID, &telemetrySequence, "kubernetes_client_init_failed")
		return errors.Wrap(err, "failed to create kube client")
	}
	if clusterName != "" {
		kubeClientCtx, kubeClientCancel := context.WithTimeout(context.Background(), apiContextTimeout)
		err := frontClient.PostDaemonsetAgentTelemetry(kubeClientCtx, rest.DaemonsetTelemetryRequest{
			Type:              rest.TelemetryTypeEvents,
			Event:             "kubernetes_client_ready",
			AgentID:           agentID,
			Sequence:          atomic.AddUint64(&telemetrySequence, 1),
			SchemaVersion:     "v1",
			KubernetesCluster: clusterName,
			UserID:            agentUserID,
			TeamID:            agentTeamID,
		})
		kubeClientCancel()
		if err != nil {
			printer.Errorf("Failed to send kubernetes_client_ready telemetry: %v\n", err)
		}
	}

	criClient, err := cri_apis.NewCRIClient()
	if err != nil {
		sendAgentFailed(frontClient, agentID, clusterName, agentUserID, agentTeamID, &telemetrySequence, "cri_client_init_failed")
		return errors.Wrap(err, "failed to create CRI client")
	}

	daemonsetRun := &Daemonset{
		ClusterName:              clusterName,
		InsightsEnvironment:      os.Getenv(POSTMAN_INSIGHTS_ENV),
		InsightsUserID:           agentUserID,
		InsightsTeamID:           agentTeamID,
		InsightsReproModeEnabled: args.ReproMode,
		InsightsRateLimit:        args.RateLimit,
		KubeClient:               kubeClient,
		CRIClient:                criClient,
		FrontClient:              frontClient,
		TelemetryInterval:        telemetryInterval,
		PodHealthCheckInterval:   DefaultPodHealthCheckInterval,
		DiscoveryMode:            args.DiscoveryMode,
		EnableHTTPSCapture:       args.EnableHTTPSCapture,
		HTTPSRateCapPerSec:       args.HTTPSRateCapPerSec,
		HTTPSBodySizeCap:         args.HTTPSBodySizeCap,
		HTTPSCBPFExcludePort:     args.HTTPSCBPFExcludePort,
		HTTPSNoThermostat:        args.HTTPSNoThermostat,
		Coverage:                 coverage,
		AgentID:                  agentID,
		telemetrySequence:        telemetrySequence,
		telemetryWindowStart:     time.Now().UTC(),
		agentState:               rest.AgentStateHealthy,
		agentStateSince:          time.Now().UTC(),
	}

	// In discovery mode, read the DaemonSet-level API key and initialize the pod filter.
	if args.DiscoveryMode {
		apiKey := os.Getenv(POSTMAN_INSIGHTS_API_KEY)
		if apiKey == "" {
			sendAgentFailed(frontClient, agentID, clusterName, agentUserID, agentTeamID, &telemetrySequence, "discovery_api_key_missing")
			return errors.New("discovery mode requires an API key (set POSTMAN_INSIGHTS_API_KEY)")
		}
		daemonsetRun.InsightsAPIKey = apiKey
		podFilter, err := NewPodFilter(
			daemonsetRun.KubeClient.AgentHost,
			args.IncludeNamespaces,
			args.ExcludeNamespaces,
			args.IncludeLabels,
			args.ExcludeLabels,
		)
		if err != nil {
			sendAgentFailed(frontClient, agentID, clusterName, agentUserID, agentTeamID, &telemetrySequence, "pod_filter_init_failed")
			return errors.Wrap(err, "failed to create pod filter")
		}
		daemonsetRun.PodFilter = podFilter
		printer.Infof("Discovery mode enabled. Using DaemonSet-level API key.\n")
	}
	// Initialise a shared NodeCollector once per agent pod when HTTPS capture
	// is enabled. This loads the eBPF programs exactly once for all pods on
	// this node, instead of once per monitored pod.
	if args.EnableHTTPSCapture {
		nc, err := ebpf.NewNodeCollector(ebpf.NodeCollectorConfig{
			MaxCaptureBytes:   args.HTTPSBodySizeCap,
			RateCapPerSec:     args.HTTPSRateCapPerSec,
			DisableThermostat: args.HTTPSNoThermostat,
		})
		if err != nil {
			printer.Warningf(
				"ebpf: failed to initialise node-scoped BPF collector (%v); "+
					"HTTPS capture will be disabled for all monitored pods on this node.\n", err)
		} else {
			daemonsetRun.EBPFNodeCollector = nc
			printer.Infof("ebpf: node-scoped BPF collector initialised (one loader for all pods on this node)\n")
		}
	}

	if err := daemonsetRun.Run(); err != nil {
		return cmderr.AkitaErr{Err: err}
	}

	// Clean up the shared NodeCollector after Run() returns.
	if daemonsetRun.EBPFNodeCollector != nil {
		_ = daemonsetRun.EBPFNodeCollector.Close()
	}

	return nil
}

// Run starts the Daemonset and its workers, and waits for a termination signal.
// It performs the following steps:
// 1. Starts all the workers.
// 4. Starts the process in the existing pods.
// 5. Waits for a termination signal (SIGINT or SIGTERM).
// 6. Signals all workers to stop.
// 7. Stops all apidump processes.
// 8. Exits the daemonset agent.
func (d *Daemonset) Run() error {
	printer.Infof("Starting daemonset agent...\n")
	done := make(chan struct{})
	var healthWorkerWG sync.WaitGroup

	// Start the shared eBPF node collector's event-dispatch loop when enabled.
	// This must be running before any per-pod Subscribe() calls are made.
	if d.EBPFNodeCollector != nil {
		nodeCtx, cancelNode := context.WithCancel(context.Background())
		go func() {
			<-done
			cancelNode()
		}()
		go func() {
			if err := d.EBPFNodeCollector.Run(nodeCtx); err != nil {
				printer.Warningf("ebpf: node-collector stopped: %v\n", err)
			}
		}()
		printer.Infof("ebpf: node-collector event loop started\n")
	}

	// Start the telemetry worker
	printer.Infof("Starting telemetry worker...\n")
	go d.TelemetryWorker(done)

	// Start the pods health worker
	printer.Infof("Starting pods health worker...\n")
	healthWorkerWG.Add(1)
	go func() {
		defer healthWorkerWG.Done()
		d.PodsHealthWorker(done)
	}()

	// Start the process in the existing pods
	printer.Infof("Starting process in existing pods...\n")
	err := d.StartProcessInExistingPods()
	if err != nil {
		printer.Errorf("Failed to start process in existing pods, error: %v\n", err)
		printer.Errorf("Agent will not listen traffic from existing pods\n")
	}

	// Register handlers after reconciling the synchronized cache. The informer
	// replays cached objects to newly registered handlers, so Add must be idempotent.
	if err := d.registerPodEventHandlers(done); err != nil {
		close(done)
		d.stopPodEventDispatcher()
		healthWorkerWG.Wait()
		d.KubeClient.Close()
		d.StopAllApiDumpProcesses()
		sendAgentFailed(d.FrontClient, d.AgentID, d.ClusterName, d.InsightsUserID, d.InsightsTeamID, &d.telemetrySequence, "informer_registration_failed")
		return errors.Wrap(err, "failed to register pod informer handlers")
	}
	if err := d.reconcileMissingPodsAfterStartup(); err != nil {
		close(done)
		d.stopPodEventDispatcher()
		healthWorkerWG.Wait()
		d.KubeClient.Close()
		d.StopAllApiDumpProcesses()
		sendAgentFailed(d.FrontClient, d.AgentID, d.ClusterName, d.InsightsUserID, d.InsightsTeamID, &d.telemetrySequence, "pod_reconciliation_failed")
		return errors.Wrap(err, "failed to reconcile pods after registering informer handlers")
	}

	printer.Infof("Send SIGINT (Ctrl-C) to stop...\n")

	// Wait for signal to stop
	{
		sig := make(chan os.Signal, 2)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

		// Continue until an interrupt
		for received := range sig {
			printer.Stderr.Infof("Received %v, stopping daemonset...\n", received.String())
			break
		}
	}

	// Signal all workers to stop
	printer.Debugf("Signaling all workers to stop...\n")
	close(done)
	d.stopPodEventDispatcher()
	healthWorkerWG.Wait()

	// Stop and wait for the pod informer before stopping capture processes.
	printer.Debugf("Stopping k8s pod informer...\n")
	d.KubeClient.Close()

	// Stop all apidump processes
	printer.Debugf("Stopping all apidump processes...\n")
	d.StopAllApiDumpProcesses()

	d.sendAgentStopped()

	printer.Infof("Exiting daemonset agent...\n")
	return nil
}

// sendAgentStopped flushes any counters accumulated since the last heartbeat
// and reports a terminal agent_stopped event, so a graceful shutdown leaves a
// clear end-of-run marker instead of just going quiet until the next
// heartbeat would have been due. The flushed counters ride along as Events on
// this same POST, rather than as separate requests.
func (d *Daemonset) sendAgentStopped() {
	if d.ClusterName == "" {
		return
	}
	events := d.drainTelemetryEvents(time.Now().UTC())

	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()
	err := d.FrontClient.PostDaemonsetAgentTelemetry(ctx, rest.DaemonsetTelemetryRequest{
		Type:              rest.TelemetryTypeEvents,
		Event:             "agent_stopped",
		AgentID:           d.AgentID,
		Sequence:          atomic.AddUint64(&d.telemetrySequence, 1),
		SchemaVersion:     "v1",
		KubernetesCluster: d.ClusterName,
		UserID:            d.InsightsUserID,
		TeamID:            d.InsightsTeamID,
		AgentVersion:      version.ReleaseVersion().String(),
		GitVersion:        version.GitVersion(),
		Events:            events,
	})
	if err != nil {
		printer.Errorf("Failed to send agent_stopped telemetry: %v\n", err)
	}
}

// resolveAgentIdentity looks up the Postman user and team that own this
// agent's DaemonSet-level API key, for stamping on agent-scope telemetry.
// Since the backend takes the agent-reported user/team as the sole tenancy
// attribution for a row, this is what makes agent lifecycle events
// attributable to a customer at all.
//
// Best-effort by design: only discovery mode requires a DaemonSet-level API
// key, so a workspace-mode agent legitimately has none and reports empty
// identity rather than failing to start. Telemetry attribution is not worth
// blocking traffic capture over -- per-pod counters still carry their own
// target-scoped identity from each pod's own key. A lookup failure is logged
// and treated the same way.
func resolveAgentIdentity(telemetryDomain string) (userID, teamID string) {
	apiKey := os.Getenv(POSTMAN_INSIGHTS_API_KEY)
	if apiKey == "" {
		printer.Debugf(
			"No DaemonSet-level API key set; agent-scope telemetry will be sent without a " +
				"user or team and cannot be attributed to a Postman team.\n",
		)
		return "", ""
	}

	identityClient := rest.NewFrontClient(
		telemetryDomain,
		telemetry.GetClientID(),
		rest.ApiDumpDaemonsetAuthHandler(apiKey, os.Getenv(POSTMAN_INSIGHTS_ENV)),
		nil,
	)
	if viper.GetBool("test_only_disable_telemetry_https") {
		identityClient.UseInsecureScheme()
	}

	trackingUser, err := telemetry.GetTrackingUserAssociatedWithAPIKey(identityClient)
	if err != nil {
		printer.Debugf(
			"Failed to resolve the agent's Postman identity: %v. Agent-scope telemetry will "+
				"be sent without a user or team.\n",
			err,
		)
		return "", ""
	}
	return trackingUser.UserID, trackingUser.TeamID
}

// sendAgentFailed reports a terminal, agent-scope startup/runtime failure with
// a normalized category. Used both before the Daemonset struct exists (early
// StartDaemonset failures) and from within Run(), so it takes its telemetry
// coordinates directly rather than a *Daemonset receiver.
func sendAgentFailed(
	frontClient rest.FrontClient,
	agentID, clusterName, userID, teamID string,
	sequence *uint64,
	category string,
) {
	if clusterName == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()
	err := frontClient.PostDaemonsetAgentTelemetry(ctx, rest.DaemonsetTelemetryRequest{
		Type:              rest.TelemetryTypeEvents,
		Event:             "agent_failed",
		AgentID:           agentID,
		Sequence:          atomic.AddUint64(sequence, 1),
		SchemaVersion:     "v1",
		KubernetesCluster: clusterName,
		UserID:            userID,
		TeamID:            teamID,
		FailureCategory:   category,
	})
	if err != nil {
		printer.Errorf("Failed to send agent_failed telemetry: %v\n", err)
	}
}

// getPodArgsFromMap retrieves the PodArgs associated with the given podUID from the PodArgsByNameMap.
// If the PodArgs are found, they are returned. Otherwise, an error is returned indicating that the PodArgs
// were not found for the specified podUID.
func (d *Daemonset) getPodArgsFromMap(podUID types.UID) (*PodArgs, error) {
	var podArgs *PodArgs
	if p, ok := d.PodArgsByNameMap.Load(podUID); ok {
		podArgs = p.(*PodArgs)
	} else {
		return podArgs, errors.Errorf("podArgs not found for podId: %s", podUID)
	}

	return podArgs, nil
}

// addPodArgsToMap adds the podArgs to the map with the podUID as the key
// This function ensures that the pod is not already loaded in the map
func (d *Daemonset) addPodArgsToMap(podUID types.UID, args *PodArgs, startingState PodTrafficMonitorState) error {
	value, loaded := d.PodArgsByNameMap.LoadOrStore(podUID, args)
	argsFromMap := value.(*PodArgs)
	if !loaded {
		err := argsFromMap.changePodTrafficMonitorState(startingState)
		if err != nil {
			return errors.Wrapf(err, "failed to change pod state, pod name: %s, from: %s to: %s",
				argsFromMap.PodName, argsFromMap.PodTrafficMonitorState, startingState)
		}
	} else {
		return errors.Errorf("pod is already loaded in the map and is in state %s", argsFromMap.PodTrafficMonitorState)
	}

	return nil
}

// TelemetryWorker starts a worker that periodically sends telemetry data and dumps the state of the Pods API dump process.
// The worker runs until the provided done channel is closed.
func (d *Daemonset) TelemetryWorker(done <-chan struct{}) {
	if d.TelemetryInterval <= 0 {
		printer.Debugf("Telemetry interval is set to 0, telemetry worker will not run\n")
		return
	}

	ticker := time.NewTicker(d.TelemetryInterval)

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			d.sendTelemetry()
			d.dumpPodsApiDumpProcessState()
		}
	}
}

// StartProcessInExistingPods starts apidump process in existing pods
// that do not have the agent sidecar container and required env vars.
func (d *Daemonset) StartProcessInExistingPods() error {
	// Get all pods in the node where the agent is running
	pods, err := d.KubeClient.GetPodsInAgentNode()
	if err != nil {
		return errors.Wrap(err, "failed to get pods in node")
	}
	// Filter out pods that do not have the agent sidecar container
	podsWithoutAgentSidecar, err := d.KubeClient.FilterPodsByContainerImage(pods, agentImage, true)
	if err != nil {
		return errors.Wrap(err, "failed to filter pods by container image")
	}

	// Discovery is observed after the sidecar filter, matching
	// handlePodAddEvent: a pod carrying the agent sidecar belongs to that
	// sidecar's funnel, not this one, and entering it here would strand it at
	// pod_discovered holding a maxTargets slot forever (see the filter branch
	// in handlePodAddEvent for why it can never become evictable).
	for _, pod := range podsWithoutAgentSidecar {
		d.observeCoverage(pod, CoveragePodDiscovered, "", "")
	}

	// Iterate over each pod without the agent sidecar
	for _, pod := range podsWithoutAgentSidecar {
		// In discovery mode, apply pod filter before processing.
		if d.DiscoveryMode && d.PodFilter != nil {
			result := d.PodFilter.Evaluate(pod)
			if !result.ShouldCapture {
				d.observeCoverage(pod, CoverageDiscoveryFilterRejected, result.Reason, "")
				printer.Debugf("Pod %s/%s skipped by discovery filter: %s\n", pod.Namespace, pod.Name, result.Reason)
				continue
			}
			d.observeCoverage(pod, CoverageDiscoveryFilterPassed, "passed_filters", result.ServiceName)
			printer.Debugf("Pod %s/%s passed discovery filter, service: %s\n", pod.Namespace, pod.Name, result.ServiceName)
		}

		// Empty pod_args object for PodPending state
		args := NewPodArgs(pod.Name)
		err := d.inspectPodForEnvVars(pod, args)
		if err != nil {
			d.observeCoverage(pod, CoveragePodConfigurationFailed, "configuration_error", "")
			d.observeCoverageError(pod, err)
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
		d.observeCoverage(pod, CoveragePodConfigured, "configured", "")
		if d.Coverage != nil {
			d.Coverage.SetProjectInfo(string(pod.UID), akid.String(args.InsightsProjectID), args.WorkspaceID)
		}

		err = d.addPodArgsToMap(pod.UID, args, PodRunning)
		if err != nil {
			printer.Errorf("Failed to add pod args to map, pod name: %s, error: %v\n", pod.Name, err)
			continue
		}

		err = d.StartApiDumpProcess(pod.UID)
		if err != nil {
			// StartApiDumpProcess only fails on a local bookkeeping error
			// (missing pod args, or a pod-state-machine violation) before the
			// capture goroutine is even launched -- this pod will never be
			// monitored from this attempt, which is what CoveragePodFailed
			// means, not a transient step on the way to capturing.
			d.observeCoverage(pod, CoveragePodFailed, "apidump_start_failed", "")
			printer.Errorf("Failed to start api dump process, pod name: %s, error: %v\n", pod.Name, err)
			continue
		}
	}

	return nil
}

// PodsHealthWorker periodically checks the health of the pods and prunes stopped processes.
// It runs until the provided done channel is closed.
func (d *Daemonset) PodsHealthWorker(done <-chan struct{}) {
	if d.PodHealthCheckInterval <= 0 {
		printer.Debugf("Pod health check interval is set to 0, pods health worker will not run\n")
		return
	}

	ticker := time.NewTicker(d.PodHealthCheckInterval)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			d.checkPodsHealth()
			d.pruneStoppedProcesses()
		}
	}
}

// StopAllApiDumpProcesses stops all API dump processes for the Daemonset.
// It iterates over the PodArgsByNameMap and performs the following actions for each pod:
// 1. Changes the pod's traffic monitor state to DaemonSetShutdown.
// 2. Stops the API dump process for the pod.
// 3. Logs any errors encountered during the state change or stopping process.
// 4. Removes the pod from the PodArgsByNameMap.
// 5. Wait for all the apidump processes to stop.
func (d *Daemonset) StopAllApiDumpProcesses() {
	d.PodArgsByNameMap.Range(func(k, v interface{}) bool {
		podUID := k.(types.UID)
		podArgs := v.(*PodArgs)

		// Since this state can happen at any time so no check for allowed current states
		err := podArgs.changePodTrafficMonitorState(DaemonSetShutdown)
		if err != nil {
			printer.Errorf("Failed to change pod state, pod name: %s, from: %s to: %s, error: %v\n",
				podArgs.PodName, podArgs.PodTrafficMonitorState, DaemonSetShutdown, err)
			return true
		}

		err = d.SignalApiDumpProcessToStop(podUID, errors.Errorf("Daemonset agent is shutting down, stopping pod: %s", podArgs.PodName))
		if err != nil {
			printer.Errorf("Failed to stop api dump process, pod name: %s, error: %v\n", podArgs.PodName, err)
		}

		// Remove the pod from the map
		d.PodArgsByNameMap.Delete(podUID)
		return true
	})

	// Wait for all apidump processes to stop
	printer.Debugf("Waiting for all apidump processes to stop...\n")
	d.ApidumpProcessesWG.Wait()
}
