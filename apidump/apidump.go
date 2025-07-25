package apidump

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akiuri"
	"github.com/akitasoftware/akita-libs/api_schema"
	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/architecture"
	"github.com/postmanlabs/postman-insights-agent/ci"
	"github.com/postmanlabs/postman-insights-agent/data_masks"
	"github.com/postmanlabs/postman-insights-agent/deployment"
	"github.com/postmanlabs/postman-insights-agent/env"
	"github.com/postmanlabs/postman-insights-agent/location"
	"github.com/postmanlabs/postman-insights-agent/pcap"
	"github.com/postmanlabs/postman-insights-agent/plugin"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/tcp_conn_tracker"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/tls_conn_tracker"
	"github.com/postmanlabs/postman-insights-agent/trace"
	"github.com/postmanlabs/postman-insights-agent/usage"
	"github.com/postmanlabs/postman-insights-agent/util"
	"github.com/postmanlabs/postman-insights-agent/version"
	"github.com/spf13/viper"
)

// TODO(kku): make pcap timings more robust (e.g. inject a sentinel packet to
// mark start and end of pcap).
const (
	// Empirically, it takes 1s for pcap to be ready to process packets.
	// We budget for 5x to be safe.
	pcapStartWaitTime = 5 * time.Second

	// Empirically, it takes 1s for the first packet to become available for
	// processing.
	// We budget for 5x to be safe.
	pcapStopWaitTime = 5 * time.Second

	// Number of top ports to show in telemetry
	topNForSummary = 10

	// Context timeout for telemetry upload
	telemetryTimeout = 30 * time.Second
)

const (
	subcommandOutputDelimiter = "======= _POSTMAN_SUBCOMMAND_ ======="
)

type filterState string

const (
	matchedFilter    filterState = "MATCHED"
	notMatchedFilter filterState = "UNMATCHED"
)

var ProcessSignalErr = errors.New("process received exit signal")

// Args for running apidump as daemonset in Kubernetes
type DaemonsetArgs struct {
	TargetNetworkNamespaceOpt string
	StopChan                  <-chan error `json:"-"`
	APIKey                    string
	Environment               string
	TraceTags                 tags.SingletonTags
}

type Args struct {
	// Required args
	ClientID akid.ClientID
	Domain   string

	// Optional args

	// If both LocalPath and AkitaURI are set, data is teed to both local traces
	// and backend trace.
	// If unset, defaults to a random spec name on Akita Cloud.
	Out location.Location

	// Args used to using agent with Postman
	PostmanCollectionID string

	// ServiceID parsed from projectID
	ServiceID akid.ServiceID

	Interfaces     []string
	Filter         string
	Tags           map[tags.Key]string
	PathExclusions []string
	HostExclusions []string
	PathAllowlist  []string
	HostAllowlist  []string

	// Rate-limiting parameters -- only one should be set to a non-default value.
	SampleRate         float64
	WitnessesPerMinute float64

	// If set, apidump will run the command in a subshell and terminate
	// automatically when the subcommand terminates.
	//
	// apidump will pipe stdout and stderr from the command. If the command stops
	// with non-zero exit code, apidump will also exit with the same exit code.
	ExecCommand string

	// Username to run ExecCommand as. If not set, defaults to the current user.
	ExecCommandUser string

	Plugins []plugin.AkitaPlugin

	// How often to rotate learn sessions; set to zero to disable rotation.
	LearnSessionLifetime time.Duration

	// Periodically report telemetry every N seconds thereafter
	TelemetryInterval int

	// Periodically poll /proc fs for agent resource usage every N seconds.
	ProcFSPollingInterval int

	// Whether to report TCP connections and TLS handshakes.
	CollectTCPAndTLSReports bool

	// Parse TLS handshake messages (even if not reported)
	// Invariant: this is true if CollectTCPAndTLSReports is true
	ParseTLSHandshakes bool

	// The maximum witness size to upload. Anything larger is dropped.
	MaxWitnessSize_bytes int

	// Whether to run the command with additional functionality to support the Docker Extension
	DockerExtensionMode bool
	// The port to be used by the Docker Extension for health checks
	HealthCheckPort int

	// Whether to enable repro mode and include request/response payloads when uploading witnesses.
	ReproMode bool

	// Whether to drop traffic to/from nginx
	DropNginxTraffic bool

	DaemonsetArgs optionals.Optional[DaemonsetArgs]

	// The number of upload buffers. Anything larger than 1 results in async uploads.
	MaxWitnessUploadBuffers int
}

// TODO: either remove write-to-local-HAR-file completely,
// or refactor into a separate class to avoid all the branching.
type apidump struct {
	*Args

	backendSvc     akid.ServiceID
	backendSvcName string
	learnClient    rest.LearnClient

	startTime        time.Time
	dumpSummary      *Summary
	successTelemetry *trace.SuccessTelemetry
}

// Start a new apidump session based on the given arguments.
func newSession(args *Args) *apidump {
	a := &apidump{
		Args:      args,
		startTime: time.Now(),
		successTelemetry: &trace.SuccessTelemetry{
			Channel: make(chan struct{}),
			Once:    sync.Once{},
		},
	}
	return a
}

// Is the target the Akita backend as expected, or a local HAR file?
func (a *apidump) TargetIsRemote() bool {
	return a.Out.AkitaURI != nil || a.PostmanCollectionID != "" || a.ServiceID != akid.ServiceID{}
}

// Lookup the service and create a learn client targeting it.
func (a *apidump) LookupService() error {
	if !a.TargetIsRemote() {
		return nil
	}

	// Set auth handler for processes starting via daemonset
	var authHandler func(*http.Request) error
	if daemonsetArgs, exists := a.DaemonsetArgs.Get(); exists {
		authHandler = rest.ApiDumpDaemonsetAuthHandler(daemonsetArgs.APIKey, daemonsetArgs.Environment)
	}

	frontClient := rest.NewFrontClient(a.Domain, a.ClientID, authHandler)

	if a.PostmanCollectionID != "" {
		backendSvc, err := util.GetOrCreateServiceIDByPostmanCollectionID(frontClient, a.PostmanCollectionID)
		if err != nil {
			return err
		}

		a.backendSvc = backendSvc
		a.backendSvcName = "Postman_Collection_" + a.PostmanCollectionID
	} else {
		serviceName, err := util.GetServiceNameByServiceID(frontClient, a.ServiceID)
		if err != nil {
			return err
		}

		a.backendSvc = a.ServiceID
		a.backendSvcName = serviceName
	}

	a.learnClient = rest.NewLearnClient(a.Domain, a.ClientID, a.backendSvc, authHandler)
	return nil
}

// Send the initial message to the backend indicating successful start
func (a *apidump) SendInitialTelemetry() {
	// Do not send packet capture telemetry for local captures.
	if !a.TargetIsRemote() {
		return
	}

	// XXX(cns):  The observed duration serves as a key for upserting packet
	//    telemetry, so it needs to be the same here as in the packet
	//    telemetry sent 5 minutes after startup.
	req := kgxapi.PostInitialClientTelemetryRequest{
		ClientID:                  a.ClientID,
		ObservedStartingAt:        a.startTime,
		ObservedDurationInSeconds: 0,
		SendsWitnessPayloads:      a.ReproMode,
		CLIVersion:                version.ReleaseVersion().String(),
		CLITargetArch:             architecture.GetCanonicalArch(),
		AkitaDockerRelease:        env.InDocker(),
		DockerDesktop:             env.HasDockerInternalHostAddress(),
		AgentRateLimit:            a.WitnessesPerMinute,
	}

	if pod, present := a.Args.Tags[tags.XAkitaKubernetesPod]; present {
		req.MonitoredPodName = pod
		hostname, err := os.Hostname()
		if err == nil {
			req.AgentPodName = hostname
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
	defer cancel()
	err := a.learnClient.PostInitialClientTelemetry(ctx, a.backendSvc, req)
	if err != nil {
		// Log an error and continue.
		printer.Stderr.Errorf("Failed to send initial telemetry statistics: %s\n", err)
		telemetry.Error("telemetry", err)
	}
}

// Send a message to the backend indicating failure to start and a cause
func (a *apidump) SendErrorTelemetry(errorType api_schema.ApidumpErrorType, err error) {
	req := &kgxapi.PostClientPacketCaptureStatsRequest{
		ObservedDurationInSeconds: a.TelemetryInterval,
		ApidumpError:              errorType,
		ApidumpErrorText:          err.Error(),
	}
	a.SendTelemetry(req)
}

// Helper method to detect filter errors
func isBpfFilterError(e error) bool {
	// FIXME: can't use errors.Is because we don't have a class for this.
	return strings.Contains(e.Error(), "failed to set BPF filter")
}

// Update the backend with new current capture stats.
func (a *apidump) SendPacketTelemetry(observationDuration int, windowStartTime time.Time, windowDuration int) {
	req := &kgxapi.PostClientPacketCaptureStatsRequest{
		AgentResourceUsage:              usage.Get(),
		ObservedDurationInSeconds:       observationDuration,
		ObservedWindowStartingAt:        windowStartTime,
		ObservedWindowDurationInSeconds: windowDuration,
		AgentRateLimit:                  a.WitnessesPerMinute,
	}
	if a.dumpSummary != nil {
		req.PacketCountSummary = a.dumpSummary.FilterSummary.Summary(topNForSummary)
	}

	a.SendTelemetry(req)
}

// Fill in the client ID and start time and send telemetry to the backend.
func (a *apidump) SendTelemetry(req *kgxapi.PostClientPacketCaptureStatsRequest) {
	// Do not send packet capture telemetry for local captures.
	if !a.TargetIsRemote() {
		return
	}

	req.ClientID = a.ClientID
	req.ObservedStartingAt = a.startTime

	ctx, cancel := context.WithTimeout(context.Background(), telemetryTimeout)
	defer cancel()
	err := a.learnClient.PostClientPacketCaptureStats(ctx, a.backendSvc, *req)
	if err != nil {
		// Log an error and continue.
		printer.Stderr.Errorf("Failed to send telemetry statistics: %s\n", err)
		telemetry.Error("telemetry", err)
	}
}

// Clean up the arguments and warn about any modifications.
func (args *Args) lint() {
	// Modifies the input to remove empty strings. Returns true if the input was
	// modified.
	removeEmptyStrings := func(strings []string) ([]string, bool) {
		i := 0
		modified := false
		for _, elt := range strings {
			if len(elt) > 0 {
				strings[i] = elt
				i++
			} else {
				modified = true
			}
		}
		strings = strings[:i]
		return strings, modified
	}

	// Empty path/host-exclusion regular expressions will exclude everything.
	// Ignore these and print a warning.
	for paramName, argsPtr := range map[string]*[]string{
		"--path-exclusions": &args.PathExclusions,
		"--host-exclusions": &args.HostExclusions,
	} {
		modified := false
		*argsPtr, modified = removeEmptyStrings(*argsPtr)
		if modified {
			printer.Stderr.Warningf("Ignoring empty regex in %s, which would otherwise exclude everything\n", paramName)
		}
	}

	// Empty path/host-inclusion regular expressions will include everything. If
	// there are any non-empty regular expressions, ignore the empty regexes and
	// print a warning.
	for paramName, argsPtr := range map[string]*[]string{
		"--path-allow": &args.PathAllowlist,
		"--host-allow": &args.HostAllowlist,
	} {
		modified := false
		*argsPtr, modified = removeEmptyStrings(*argsPtr)
		if modified && len(*argsPtr) > 0 {
			printer.Stderr.Warningf("Ignoring empty regex in %s, which would otherwise include everything\n", paramName)
		}
	}
}

// args.Tags may be initialized via the command line, but automated settings
// are mainly performed here (for now.)
func collectTraceTags(args *Args) map[tags.Key]string {
	traceTags := args.Tags
	if traceTags == nil {
		traceTags = map[tags.Key]string{}
	}
	// Store the current packet capture flags so we can reuse them in active
	// learning.
	if len(args.Interfaces) > 0 {
		traceTags[tags.XAkitaDumpInterfacesFlag] = strings.Join(args.Interfaces, ",")
	}
	if args.Filter != "" {
		traceTags[tags.XAkitaDumpFilterFlag] = args.Filter
	}

	// Set CI type and tags on trace
	ciType, _, ciTags := ci.GetCIInfo()
	if ciType != ci.Unknown {
		for k, v := range ciTags {
			traceTags[k] = v
		}
		traceTags[tags.XAkitaSource] = tags.CISource
	}

	// Set legacy deployment tags.
	traceTags[tags.XAkitaDeployment] = apispec.DefaultDeployment
	traceTags[tags.XAkitaSource] = tags.DeploymentSource

	// Set tags from the daemonSet apidump process
	// Here we expect that the parent go routine has already set the tags
	// if DaemonsetArgs is set.
	if dArgs, exists := args.DaemonsetArgs.Get(); exists {
		for k, v := range dArgs.TraceTags {
			traceTags[k] = v
		}
	} else {
		deployment.UpdateTags(traceTags)
		hostname, err := os.Hostname()
		if err == nil {
			traceTags[tags.XInsightsHostname] = hostname
		}
	}

	// Set source to user by default (if not CI or deployment)
	if _, ok := traceTags[tags.XAkitaSource]; !ok {
		traceTags[tags.XAkitaSource] = tags.UserSource
	}

	printer.Debugln("trace tags:", traceTags)
	return traceTags
}

func compileRegexps(filters []string, name string) ([]*regexp.Regexp, error) {
	result := make([]*regexp.Regexp, len(filters))
	for i, f := range filters {
		r, err := regexp.Compile(f)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to compile %s %q", name, f)
		}
		result[i] = r
	}
	return result, nil
}

// Periodically create a new learn session with a random name.
func (a *apidump) RotateLearnSession(done <-chan struct{}, collectors []trace.LearnSessionCollector, traceTags map[tags.Key]string) {
	var args *Args = a.Args
	t := time.NewTicker(args.LearnSessionLifetime)
	defer t.Stop()

	for {
		select {
		case <-done:
			return

		case <-t.C:
			traceName := util.RandomLearnSessionName()
			backendLrn, err := util.NewLearnSession(a.learnClient, traceName, traceTags, nil)
			if err != nil {
				telemetry.Error("new learn session", err)
				printer.Errorf("Failed to create trace %s: %v\n", traceName, err)
				break
			}
			printer.Infof("Rotating to new trace on Postman Cloud: %v\n", traceName)
			for _, c := range collectors {
				c.SwitchLearnSession(backendLrn)
			}
			telemetry.Success("rotate learn session")
		}
	}
}

// Goroutine to send telemetry, stop when "done" is closed.
//
// Sends telemetry to the server on a regular basis.
// Omits if args.TelemetryInterval is <= 0
func (a *apidump) TelemetryWorker(done <-chan struct{}) {
	if a.TelemetryInterval <= 0 {
		return
	}

	a.SendInitialTelemetry()

	subsequentTelemetrySent := false
	if a.TelemetryInterval > 0 {
		ticker := time.NewTicker(time.Duration(a.TelemetryInterval) * time.Second)

		lastReport := time.Now()
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				observationDuration := int(now.Sub(a.startTime) / time.Second)
				windowStart := lastReport
				windowDuration := int(now.Sub(windowStart) / time.Second)
				lastReport = time.Now()
				a.SendPacketTelemetry(observationDuration, windowStart, windowDuration)
				subsequentTelemetrySent = true
			case <-a.successTelemetry.Channel:
				if !subsequentTelemetrySent {
					observationDuration := int(time.Since(a.startTime) / time.Second)
					windowStart := lastReport
					windowDuration := int(time.Since(windowStart) / time.Second)
					lastReport = time.Now()
					a.SendPacketTelemetry(observationDuration, windowStart, windowDuration)
				}
			}
		}
	}
}

type interfaceError struct {
	interfaceName string
	err           error
}

// Captures packets from the network and adds them to a trace. The trace is
// created if it doesn't already exist.
func Run(args Args) error {
	errChan := make(chan error)

	// The Docker extension expects a health-check server to be running. Only
	// start this server if it's needed.
	if args.DockerExtensionMode {
		go func() {
			errChan <- startHealthCheckServer(args.HealthCheckPort)
		}()
	}

	// Run the main packet-capture loop.
	go func() {
		args.lint()

		a := newSession(&args)
		errChan <- a.Run()
	}()

	return <-errChan
}

func (a *apidump) Run() error {
	var args *Args = a.Args

	// Lookup service *first* (if we are remote) so that we can
	// send telemetry even before starting packet capture.
	// This means "sudo" problems will occur after authentication or project-name
	err := a.LookupService()
	if err != nil {
		return err
	}

	// During debugging, capture packets not matching the user's filters so we can
	// report statistics on those packets.
	capturingNegation := viper.GetBool("debug")

	if capturingNegation {
		printer.Debugln("Capturing filtered traffic for debugging.")
	}

	var (
		targetNetworkNamespace   optionals.Optional[string]
		daemonSetProcessStopChan <-chan error
	)
	if daemonsetArgs, exists := a.DaemonsetArgs.Get(); exists {
		targetNetworkNamespace = optionals.Some(daemonsetArgs.TargetNetworkNamespaceOpt)
		daemonSetProcessStopChan = daemonsetArgs.StopChan
	}

	// Get the interfaces to listen on.
	interfaces, err := getEligibleInterfaces(args.Interfaces, targetNetworkNamespace)
	if err != nil {
		a.SendErrorTelemetry(GetErrorTypeWithDefault(err, api_schema.ApidumpError_PCAPInterfaceOther), err)
		return errors.Wrap(err, "No network interfaces could be used")
	}

	// Build the user-specified filter and its negation for each interface.
	userFilters, negationFilters, err := createBPFFilters(interfaces, args.Filter, capturingNegation, 0)
	if err != nil {
		// Unfortunately the filters aren't actually parsed here.
		// An error will show up below when we call pcap.Collect()
		a.SendErrorTelemetry(api_schema.ApidumpError_InvalidFilters, err)
		return err
	}
	printer.Debugln("User-specified BPF filters:", userFilters)
	if capturingNegation {
		printer.Debugln("Negation BPF filters:", negationFilters)
	}

	traceTags := collectTraceTags(args)

	// Build path filters.
	pathExclusions, err := compileRegexps(args.PathExclusions, "path exclusion")
	if err != nil {
		a.SendErrorTelemetry(api_schema.ApidumpError_InvalidFilters, err)
		return err
	}
	hostExclusions, err := compileRegexps(args.HostExclusions, "host exclusion")
	if err != nil {
		a.SendErrorTelemetry(api_schema.ApidumpError_InvalidFilters, err)
		return err
	}
	pathAllowlist, err := compileRegexps(args.PathAllowlist, "path filter")
	if err != nil {
		a.SendErrorTelemetry(api_schema.ApidumpError_InvalidFilters, err)
		return err
	}
	hostAllowlist, err := compileRegexps(args.HostAllowlist, "host filter")
	if err != nil {
		a.SendErrorTelemetry(api_schema.ApidumpError_InvalidFilters, err)
		return err
	}

	// Validate args.Out and fill in any missing defaults.
	if uri := args.Out.AkitaURI; uri != nil {
		if uri.ObjectType == nil {
			uri.ObjectType = akiuri.TRACE.Ptr()
		} else if !uri.ObjectType.IsTrace() {
			return errors.Errorf("%q is not a Postman trace URI", uri)
		}

		// Use a random object name by default.
		if uri.ObjectName == "" {
			uri.ObjectName = util.RandomLearnSessionName()
		} else {
			if args.LearnSessionLifetime != time.Duration(0) {
				return errors.Errorf("Cannot automatically rotate sessions when a session name is provided.")
			}
		}
	} else if (args.PostmanCollectionID != "" || args.ServiceID != akid.ServiceID{}) {
		args.Out.AkitaURI = &akiuri.URI{
			ObjectType:  akiuri.TRACE.Ptr(),
			ServiceName: a.backendSvcName,
			ObjectName:  util.RandomLearnSessionName(),
		}
	}

	// If --dogfood is specified, enable assertions in the buffer-pool code.
	if viper.GetBool("dogfood") {
		buffer_pool.CheckInvariants = true
	}

	// Create a buffer pool for storing HTTP payloads.
	pool, err := buffer_pool.MakeBufferPool(20*1024*1024, 4*1024)
	if err != nil {
		return errors.Wrapf(err, "Unable to create buffer pool")
	}

	// If the output is targeted at the backend, create a shared backend
	// learn session.
	var backendLrn akid.LearnSessionID
	if a.TargetIsRemote() {
		uri := a.Out.AkitaURI
		backendLrn, err = util.NewLearnSession(a.learnClient, uri.ObjectName, traceTags, nil)
		if err == nil {
			printer.Infof("Created new trace on Postman Cloud: %s\n", uri)
		} else {
			var httpErr rest.HTTPError
			if ok := errors.As(err, &httpErr); ok && httpErr.StatusCode == 409 {
				backendLrn, err = util.GetLearnSessionIDByName(a.learnClient, uri.ObjectName)
				if err != nil {
					return errors.Wrapf(err, "failed to lookup ID for existing trace %s", uri)
				}
				printer.Infof("Adding to existing trace: %s\n", uri)
			} else {
				a.SendErrorTelemetry(api_schema.ApidumpError_TraceCreation, err)
				return errors.Wrap(err, "failed to create trace or fetch existing trace")
			}
		}
	}

	// Initialize packet counts
	filterSummary := trace.NewPacketCounter()
	negationSummary := trace.NewPacketCounter()

	numUserFilters := len(pathExclusions) + len(hostExclusions) + len(pathAllowlist) + len(hostAllowlist)
	prefilterSummary := trace.NewPacketCounter()

	// Initialized shared rate object, if we are configured with a rate limit
	var rateLimit *trace.SharedRateLimit
	if args.WitnessesPerMinute != 0.0 {
		rateLimit = trace.NewRateLimit(args.WitnessesPerMinute)
		defer rateLimit.Stop()
	}

	// Backend collectors that need trace rotation
	var toRotate []trace.LearnSessionCollector

	a.dumpSummary = NewSummary(
		capturingNegation,
		interfaces,
		negationFilters,
		numUserFilters,
		filterSummary,
		prefilterSummary,
		negationSummary,
	)

	// Synchronization for collectors + collector errors, each of which is run in a separate goroutine.
	var doneWG sync.WaitGroup
	doneWG.Add(len(userFilters) + len(negationFilters))
	errChan := make(chan interfaceError, len(userFilters)+len(negationFilters)) // buffered enough so it never blocks
	stop := make(chan struct{})

	// If we're sending traffic to the cloud, then start telemetry and stop
	// when the main collection process does.
	if a.TargetIsRemote() {
		{
			// Record the first usage immediately (sending delay = 0) since we want to include it in the success telemetry
			go usage.Poll(stop, 0, time.Duration(a.ProcFSPollingInterval)*time.Second)
		}

		go a.TelemetryWorker(stop)
	}

	redactor, err := data_masks.NewRedactor(a.backendSvc, a.learnClient)
	if err != nil {
		return errors.Wrapf(err, "unable to instantiate redactor for %s", a.backendSvc)
	}

	// Start collecting -- set up one or two collectors per interface, depending on whether filters are in use
	numCollectors := 0
	for _, filterState := range []filterState{matchedFilter, notMatchedFilter} {
		var summary *trace.PacketCounter
		var filters map[string]string
		if filterState == matchedFilter {
			filters = userFilters
			summary = filterSummary
		} else {
			filters = negationFilters
			summary = negationSummary
		}

		for interfaceName, filter := range filters {
			var collector trace.Collector

			// Build collectors from the inside out (last applied to first applied).
			//  8. Back-end collector (sink).
			//  7. Statistics.
			//  6. Subsampling.
			//  5. Path and host filters.
			//  4. Eliminate Akita CLI traffic.
			//  3. Count packets before user filters for diagnostics.
			//  2. Process TLS traffic into TLS-connection metadata.
			//  1. Aggregate TCP-packet metadata into TCP-connection metadata.

			// Back-end collector (sink).
			if filterState == notMatchedFilter {
				// During debugging, we capture the negation of the user's filters. This
				// allows us to report statistics for packets not matching the user's
				// filters. We need to avoid sending this traffic to the back end,
				// however.
				collector = trace.NewDummyCollector()
			} else {
				var backendCollector trace.Collector
				if args.Out.AkitaURI != nil {
					backendCollector = trace.NewBackendCollector(
						a.backendSvc,
						traceTags,
						backendLrn,
						a.learnClient,
						redactor,
						optionals.Some(a.MaxWitnessSize_bytes),
						summary,
						args.ReproMode,
						args.Plugins,
						args.MaxWitnessUploadBuffers,
					)

					collector = backendCollector
				} else {
					return errors.Errorf("invalid output location")
				}

				// If the backend collector supports rotation of learn session ID, then set that up.
				if lsc, ok := backendCollector.(trace.LearnSessionCollector); ok && lsc != nil {
					toRotate = append(toRotate, lsc)
				}
			}

			// Statistics.
			//
			// Count packets that have *passed* filtering (so that we know whether the
			// trace is empty or not.)  In the future we could add columns for both
			// pre- and post-filtering.
			collector = &trace.PacketCountCollector{
				PacketCounts:     summary,
				Collector:        collector,
				SuccessTelemetry: a.successTelemetry,
			}

			// Subsampling.
			collector = trace.NewSamplingCollector(args.SampleRate, collector)
			if rateLimit != nil {
				collector = rateLimit.NewCollector(collector, summary)
			}

			// Path and host filters.
			if len(hostExclusions) > 0 {
				collector = trace.NewHTTPHostFilterCollector(hostExclusions, collector)
			}
			if len(pathExclusions) > 0 {
				collector = trace.NewHTTPPathFilterCollector(pathExclusions, collector)
			}
			if len(hostAllowlist) > 0 {
				collector = trace.NewHTTPHostAllowlistCollector(hostAllowlist, collector)
			}
			if len(pathAllowlist) > 0 {
				collector = trace.NewHTTPPathAllowlistCollector(pathAllowlist, collector)
			}

			// Eliminate Akita CLI traffic, unless --dogfood has been specified
			dropDogfoodTraffic := !viper.GetBool("dogfood")

			// Construct userTrafficCollector
			if dropDogfoodTraffic || a.DropNginxTraffic {
				collector = &trace.UserTrafficCollector{
					Collector:          collector,
					DropDogfoodTraffic: dropDogfoodTraffic,
					DropNginxTraffic:   a.DropNginxTraffic,
				}
			}

			// Count packets before user filters for diagnostics
			if filterState == matchedFilter && numUserFilters > 0 {
				collector = &trace.PacketCountCollector{
					PacketCounts: prefilterSummary,
					Collector:    collector,
				}
			}

			// If this is false, we will still parse TLS client and server hello messages
			// but not process them futher.
			if args.CollectTCPAndTLSReports {
				// Process TLS traffic into TLS-connection metadata.
				collector = tls_conn_tracker.NewCollector(collector)

				// Process TCP-packet metadata into TCP-connection metadata.
				collector = tcp_conn_tracker.NewCollector(collector)
			}

			// Compute the share of the page cache that each collection process may use.
			// (gopacket does not currently permit a unified page cache for packet reassembly.)
			bufferShare := 1.0 / float32(len(negationFilters)+len(userFilters))

			numCollectors++
			go func(interfaceName, filter string) {
				defer doneWG.Done()
				// Collect trace. This blocks until stop is closed or an error occurs.
				if err := pcap.Collect(args.ServiceID, traceTags, stop, interfaceName, filter, targetNetworkNamespace, bufferShare, args.ParseTLSHandshakes, collector, summary, pool); err != nil {
					errChan <- interfaceError{
						interfaceName: interfaceName,
						err:           errors.Wrapf(err, "failed to collect trace on interface %s", interfaceName),
					}
				}
			}(interfaceName, filter)
		}
	}

	if len(toRotate) > 0 && args.LearnSessionLifetime != time.Duration(0) {
		printer.Debugf("Rotating learn sessions with interval %v\n", args.LearnSessionLifetime)
		go a.RotateLearnSession(stop, toRotate, traceTags)
	}

	{
		iNames := make([]string, 0, len(interfaces))
		for n := range interfaces {
			iNames = append(iNames, n)
		}
		printer.Stderr.Infof("Running learn mode on interfaces %s\n", strings.Join(iNames, ", "))
	}

	unfiltered := true
	for _, f := range userFilters {
		if f != "" {
			unfiltered = false
			break
		}
	}
	if unfiltered {
		printer.Stderr.Infof("%s\n", printer.Color.Yellow("--filter flag is not set; capturing all network traffic to and from your services."))
	}

	// Lets us track if the process has received a signal like SIGINT and SIGTERM.
	var processReceivedSignal os.Signal
	// Keep track of errors by interface, as well as errors from the subcommand
	// if applicable.
	errorsByInterface := make(map[string]error)
	var subcmdErr error
	if args.ExecCommand != "" {
		printer.Stderr.Infof("Running subcommand...\n\n\n")

		time.Sleep(pcapStartWaitTime)

		// Print delimiter so it's easier to differentiate subcommand output from
		// Akita output.
		// It won't appear in JSON-formatted output.
		printer.Stdout.RawOutput(subcommandOutputDelimiter)
		printer.Stderr.RawOutput(subcommandOutputDelimiter)
		cmdErr := runCommand(args.ExecCommandUser, args.ExecCommand)
		printer.Stdout.RawOutput(subcommandOutputDelimiter)
		printer.Stderr.RawOutput(subcommandOutputDelimiter)

		if cmdErr != nil {
			subcmdErr = errors.Wrap(cmdErr, "failed to run subcommand")
			telemetry.Error("subcommand", cmdErr)

			// We promised to preserve the subcommand's exit code.
			// Explicitly notify whoever is running us to exit.
			if exitErr, ok := errors.Cause(subcmdErr).(*exec.ExitError); ok {
				subcmdErr = util.ExitError{
					ExitCode: exitErr.ExitCode(),
					Err:      subcmdErr,
				}
			}
		} else {
			// Check if we have any errors on our side.
			select {
			case interfaceErr := <-errChan:
				printer.Stderr.Errorf("Encountered errors while collecting traces, stopping...\n")
				telemetry.Error("packet capture", interfaceErr.err)
				errorsByInterface[interfaceErr.interfaceName] = interfaceErr.err

				// Drain errChan.
			DoneClearingChannel:
				for {
					select {
					case interfaceErr := <-errChan:
						errorsByInterface[interfaceErr.interfaceName] = interfaceErr.err
					default:
						break DoneClearingChannel
					}
				}
			default:
				printer.Stderr.Infof("Subcommand finished successfully, stopping trace collection...\n")
			}
		}
	} else {
		// Don't sleep pcapStartWaitTime in interactive mode since the user can send
		// SIGINT while we're sleeping too and sleeping introduces visible lag.
		printer.Stderr.Infof("Send SIGINT (Ctrl-C) to stop...\n")

		// Set up signal handler to stop packet processors on SIGINT or when one of
		// the processors returns an error.
		{
			// Must use buffered channel for signals since the signal package does not
			// block when sending signals.
			sig := make(chan os.Signal, 2)
			signal.Notify(sig, os.Interrupt)
			signal.Notify(sig, syscall.SIGTERM)

			// Continue until an interrupt or all collectors have stopped with errors.
		DoneWaitingForSignal:
			for {
				select {
				case processReceivedSignal = <-sig:
					printer.Stderr.Infof("Received %v, stopping trace collection...\n", processReceivedSignal.String())
					break DoneWaitingForSignal
				case interfaceErr := <-errChan:
					errorsByInterface[interfaceErr.interfaceName] = interfaceErr.err

					telemetry.Error("packet capture", interfaceErr.err)
					if len(errorsByInterface) < numCollectors {
						printer.Stderr.Errorf("Encountered an error on interface %s, continuing with remaining interfaces.  Error: %s\n", interfaceErr.interfaceName, interfaceErr.err.Error())
					} else {
						printer.Stderr.Errorf("Encountered an error on interface %s.  Error: %s\n", interfaceErr.interfaceName, interfaceErr.err.Error())
						break DoneWaitingForSignal
					}
				case externalStopError := <-daemonSetProcessStopChan:
					printer.Stderr.Infof("Received external stop signal, error: %v\n", externalStopError)
					break DoneWaitingForSignal
				}
			}
		}
	}

	time.Sleep(pcapStopWaitTime)

	// Signal all processors to stop.
	close(stop)

	// Wait for processors to exit.
	doneWG.Wait()
	printer.Stderr.Infof("Trace collection stopped\n")

	// Print errors per interface.
	reportedFilterError := false
	if len(errorsByInterface) > 0 {
		printer.Stderr.Errorf("Encountered errors on %d / %d interfaces\n", len(errorsByInterface), numCollectors)
		for interfaceName, err := range errorsByInterface {
			// These errors we can be certain show up right away.
			// Other errors might not?  We will get them via Segment, but until we have more
			// examples I don't think we can be sure that we'll show them to the user in a
			// meaningful way.
			if isBpfFilterError(err) && !reportedFilterError {
				a.SendErrorTelemetry(api_schema.ApidumpError_InvalidFilters, err)
				reportedFilterError = true
			}
			printer.Stderr.Errorf("%12s %s\n", interfaceName, err)
		}

		// If collectors on all interfaces report errors, report trace
		// collection failed.
		if len(errorsByInterface) == numCollectors {
			telemetry.Failure("all interfaces failed")
			return errors.Errorf("trace collection failed")
		}
	}

	// If a subcommand was supplied and failed, surface the failure.
	if subcmdErr != nil {
		return errors.Wrap(subcmdErr, "trace collection failed")
	}

	// Print warnings
	a.dumpSummary.PrintWarnings()

	if a.dumpSummary.IsEmpty() {
		telemetry.Failure("empty API trace")
	} else {
		printer.Stderr.Infof("%s 🎉\n\n", printer.Color.Green("Success!"))
	}

	if processReceivedSignal != nil {
		return ProcessSignalErr
	}

	return nil
}
