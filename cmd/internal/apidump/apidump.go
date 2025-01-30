package apidump

import (
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/apidump"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/pluginloader"
	"github.com/postmanlabs/postman-insights-agent/location"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/util"
	"github.com/spf13/cobra"
)

var (
	// Optional flags
	outFlag                 location.Location
	projectID               string
	postmanCollectionID     string
	sampleRateFlag          float64
	tagsFlag                []string
	appendByTagFlag         bool
	execCommandFlag         string
	execCommandUserFlag     string
	pluginsFlag             []string
	traceRotateFlag         string
	telemetryInterval       int
	procFSPollingInterval   int
	collectTCPAndTLSReports bool
	parseTLSHandshakes      bool
	maxWitnessSize_bytes    int
	dockerExtensionMode     bool
	healthCheckPort         int

	commonApidumpFlags *CommonApidumpFlags
)

// This function will either startup apidump normally, or never return, with probability
// determined by randomizedStart/100.  The value of the command-line flag may be
// overridden by an environment variable to make it easier to apply.
// This function should be called as early as possible in case termination of
// the agent causes deployment problems.
//
// Negative values are effectively treated as 0 probability, instead of being validated.
func applyRandomizedStart() {
	prob := commonApidumpFlags.RandomizedStart

	if env := os.Getenv("POSTMAN_AGENT_RANDOM_START"); env != "" {
		override, err := strconv.Atoi(env)
		if err == nil {
			prob = override
		}
	}

	if prob < 100 {
		printer.Stdout.Infof("Starting trace with probability %d%%.\n", prob)

		// Pre-1.20, Go does not seed the default Random object :(
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		r := rng.Intn(100) // in range [0,100),
		// so 1% probability means < 1, not <= 1:
		if r < prob {
			return
		}

		printer.Stdout.Infof("This agent instance will not begin capturing data.\n")

		// Wait forever
		select {}

		// Unreachable
		os.Exit(0)
	}
}

// When run in a container or as a systemd service, we will automatically be restarted
// on failure.  But, this will not correct misconfiguration errors; we will just get stuck
// in a boot loop, which can cause disruption to the services in the same pod.
//
// Instead, we will terminate normally when no error is returned, but loop indefinitely
// on error, as if randomized start failed.
//
// FIXME: do we need custom SIGTERM or SIGINT handlers?  I do not think we do.  But, it
// might be that apidump already installed one before returning error.  Will that cause a problem?
//
// TODO: create a separate command for "run as a service" vs "run on command line"?  I don't
// think there is a reliable way to tell the context otherwise.
func apidumpRunWithoutAbnormalExit(cmd *cobra.Command, args []string) error {
	err := apidumpRunInternal(cmd, args)

	if err == nil {
		return nil
	}

	// Log the error and wait forever.
	printer.Stderr.Errorf("Error during initiaization: %v\n", err)
	printer.Stdout.Infof("This process will not exit, to avoid boot loops. Please correct the command line flags or environment and retry.\n")

	select {}
}

func apidumpRunInternal(cmd *cobra.Command, _ []string) error {
	applyRandomizedStart()

	traceTags, err := util.ParseTagsAndWarn(tagsFlag)
	if err != nil {
		return err
	}

	plugins, err := pluginloader.Load(pluginsFlag)
	if err != nil {
		return errors.Wrap(err, "failed to load plugins")
	}

	// override the project id if the environment variable is set
	if envProjectID := os.Getenv("POSTMAN_INSIGHTS_PROJECT_ID"); envProjectID != "" {
		projectID = envProjectID
	}

	// Check that exactly one of --project or --collection is specified, or POSTMAN_INSIGHTS_PROJECT_ID was set.
	if projectID == "" && postmanCollectionID == "" {
		return errors.New("Exactly one of --project or --collection must be specified, or POSTMAN_INSIGHTS_PROJECT_ID must be set.")
	}

	// If --project was given, convert projectID to serviceID.
	var serviceID akid.ServiceID
	if projectID != "" {
		err := akid.ParseIDAs(projectID, &serviceID)
		if err != nil {
			return errors.Wrap(err, "failed to parse project ID")
		}
	}

	// Look up existing trace by tags
	if appendByTagFlag {
		if outFlag.AkitaURI == nil {
			return errors.New("\"append-by-tag\" can only be used with a cloud-based trace")
		}

		if outFlag.AkitaURI.ObjectName != "" {
			return errors.New("Cannot specify a trace name together with \"append-by-tag\"")
		}

		destURI, err := util.GetTraceURIByTags(rest.Domain,
			telemetry.GetClientID(),
			outFlag.AkitaURI.ServiceName,
			traceTags,
			"append-by-tag",
		)
		if err != nil {
			return err
		}
		if destURI.ObjectName != "" {
			outFlag.AkitaURI = &destURI
		}
	}

	// Allow specification of an alternate rotation time, default 1h.
	// We can rotate the trace if we're sending the output to a cloud-based trace.
	// But, if the trace name is explicitly given, or selected by tag,
	// or we're sending the output to a local file, then we cannot rotate.
	traceRotateInterval := time.Duration(0)
	if (outFlag.AkitaURI != nil && outFlag.AkitaURI.ObjectName == "") || projectID != "" || postmanCollectionID != "" {
		if traceRotateFlag != "" {
			traceRotateInterval, err = time.ParseDuration(traceRotateFlag)
			if err != nil {
				return errors.Wrap(err, "Failed to parse trace rotation interval.")
			}
		} else {
			traceRotateInterval = apispec.DefaultTraceRotateInterval
		}
	}

	// Rate limit must be greater than zero.
	if commonApidumpFlags.RateLimit <= 0.0 {
		commonApidumpFlags.RateLimit = 1000.0
	}

	// If we collect TLS information, we have to parse it
	if collectTCPAndTLSReports {
		if !parseTLSHandshakes {
			printer.Stderr.Warningf("Overriding parse-tls-handshakes=false because TLS report collection is enabled.\n")
			parseTLSHandshakes = true
		}
	}

	args := apidump.Args{
		ClientID:                telemetry.GetClientID(),
		Domain:                  rest.Domain,
		Out:                     outFlag,
		PostmanCollectionID:     postmanCollectionID,
		ServiceID:               serviceID,
		Tags:                    traceTags,
		SampleRate:              sampleRateFlag,
		WitnessesPerMinute:      commonApidumpFlags.RateLimit,
		Interfaces:              commonApidumpFlags.Interfaces,
		Filter:                  commonApidumpFlags.Filter,
		PathExclusions:          commonApidumpFlags.PathExclusions,
		HostExclusions:          commonApidumpFlags.HostExclusions,
		PathAllowlist:           commonApidumpFlags.PathAllowlist,
		HostAllowlist:           commonApidumpFlags.HostAllowlist,
		ExecCommand:             execCommandFlag,
		ExecCommandUser:         execCommandUserFlag,
		Plugins:                 plugins,
		LearnSessionLifetime:    traceRotateInterval,
		TelemetryInterval:       telemetryInterval,
		ProcFSPollingInterval:   procFSPollingInterval,
		CollectTCPAndTLSReports: collectTCPAndTLSReports,
		ParseTLSHandshakes:      parseTLSHandshakes,
		MaxWitnessSize_bytes:    maxWitnessSize_bytes,
		DockerExtensionMode:     dockerExtensionMode,
		HealthCheckPort:         healthCheckPort,

		// TODO: remove the SendWitnessPayloads flag once all existing users are migrated to new flag.
		ReproMode: commonApidumpFlags.EnableReproMode || commonApidumpFlags.SendWitnessPayloads,
	}
	if err := apidump.Run(args); err != nil {
		return cmderr.AkitaErr{Err: err}
	}
	return nil
}

var Cmd = &cobra.Command{
	Use:          "apidump",
	Short:        "Capture requests/responses from network traffic.",
	Long:         "Capture and store a sequence of requests/responses to a service by observing network traffic.",
	SilenceUsage: true,
	Args:         cobra.ExactArgs(0),
	RunE:         apidumpRunWithoutAbnormalExit,
}

func init() {
	Cmd.Flags().StringVar(
		&projectID,
		"project",
		"",
		"Your Postman Insights projectID.")

	Cmd.Flags().StringVar(
		&postmanCollectionID,
		"collection",
		"",
		"Your Postman collectionID. Exactly one of --project, --collection must be specified.")
	Cmd.Flags().MarkDeprecated("collection", "Use --project instead.")

	Cmd.MarkFlagsMutuallyExclusive("project", "collection")

	Cmd.Flags().Float64Var(
		&sampleRateFlag,
		"sample-rate",
		1.0,
		"A number between [0.0, 1.0] to control sampling.",
	)
	Cmd.Flags().MarkDeprecated("sample-rate", "use --rate-limit instead.")

	Cmd.Flags().StringSliceVar(
		&tagsFlag,
		"tags",
		nil,
		`Adds tags to the dump. Specified as a comma separated list of "key=value" pairs.`,
	)

	Cmd.Flags().BoolVar(
		&appendByTagFlag,
		"append-by-tag",
		false,
		"Add to the most recent trace with matching tag.")
	Cmd.Flags().MarkDeprecated("append-by-tag", "and is no longer necessary. All traces in a project are now combined into a single model. Please remove this flag.")

	Cmd.Flags().StringVarP(
		&execCommandFlag,
		"command",
		"c",
		"",
		"Command to generate API traffic.",
	)

	Cmd.Flags().StringVarP(
		&execCommandUserFlag,
		"user",
		"u",
		"",
		"User to use when running command specified by -c. Defaults to current user.",
	)

	Cmd.Flags().StringSliceVar(
		&pluginsFlag,
		"plugins",
		nil,
		"Paths of third-party plugins. They are executed in the order given.",
	)
	Cmd.Flags().MarkHidden("plugins")

	Cmd.Flags().StringVar(
		&traceRotateFlag,
		"trace-rotate",
		"",
		"Interval at which the trace will be rotated to a new learn session.",
	)
	Cmd.Flags().MarkHidden("trace-rotate")

	Cmd.Flags().IntVar(
		&telemetryInterval,
		"telemetry-interval",
		apispec.DefaultTelemetryInterval_seconds,
		"Upload client telemetry every N seconds.",
	)
	Cmd.Flags().MarkHidden("telemetry-interval")

	Cmd.Flags().IntVar(
		&procFSPollingInterval,
		"proc-polling-interval",
		apispec.DefaultProcFSPollingInterval_seconds,
		"Collect agent resource usage from the /proc filesystem (if available) every N seconds.",
	)
	Cmd.Flags().MarkHidden("proc-polling-interval")

	Cmd.Flags().BoolVar(
		&collectTCPAndTLSReports,
		"report-tcp-and-tls",
		apispec.DefaultCollectTCPAndTLSReports,
		"Collect TCP and TLS reports.",
	)
	Cmd.Flags().MarkHidden("report-tcp-and-tls")

	Cmd.Flags().BoolVar(
		&parseTLSHandshakes,
		"parse-tls-handshakes",
		apispec.DefaultParseTLSHandshakes,
		"Parse TLS handshake packets.",
	)
	Cmd.Flags().MarkHidden("parse-tls-handshakes")

	Cmd.Flags().IntVar(
		&maxWitnessSize_bytes,
		"max-witness-size-bytes",
		apispec.DefaultMaxWitnessSize_bytes,
		"Don't send witnesses larger than this.",
	)
	Cmd.Flags().MarkHidden("max-witness-size-bytes")

	Cmd.Flags().BoolVar(
		&dockerExtensionMode,
		"docker-ext-mode",
		false,
		"Enables Docker extension mode. This is an internal flag used by the Akita Docker extension.",
	)
	_ = Cmd.Flags().MarkHidden("docker-ext-mode")

	Cmd.Flags().IntVar(
		&healthCheckPort,
		"health-check-port",
		50343,
		"Port to listen on for Docker extension health checks. This is an internal flag used by the Akita Docker extension.",
	)
	_ = Cmd.Flags().MarkHidden("health-check-port")

	commonApidumpFlags = AddCommonApiDumpFlags(Cmd)
}
