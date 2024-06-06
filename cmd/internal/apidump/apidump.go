package apidump

import (
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
	interfacesFlag          []string
	filterFlag              string
	sampleRateFlag          float64
	rateLimitFlag           float64
	tagsFlag                []string
	appendByTagFlag         bool
	pathExclusionsFlag      []string
	hostExclusionsFlag      []string
	pathAllowlistFlag       []string
	hostAllowlistFlag       []string
	execCommandFlag         string
	execCommandUserFlag     string
	pluginsFlag             []string
	traceRotateFlag         string
	statsLogDelay           int
	telemetryInterval       int
	procFSPollingInterval   int
	collectTCPAndTLSReports bool
	parseTLSHandshakes      bool
	maxWitnessSize_bytes    int
	dockerExtensionMode     bool
	healthCheckPort         int
)

var Cmd = &cobra.Command{
	Use:          "apidump",
	Short:        "Capture requests/responses from network traffic.",
	Long:         "Capture and store a sequence of requests/responses to a service by observing network traffic.",
	SilenceUsage: true,
	Args:         cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, _ []string) error {
		traceTags, err := util.ParseTagsAndWarn(tagsFlag)
		if err != nil {
			return err
		}

		plugins, err := pluginloader.Load(pluginsFlag)
		if err != nil {
			return errors.Wrap(err, "failed to load plugins")
		}

		// Check that exactly one of --project or --collection is specified.
		if projectID == "" && postmanCollectionID == "" {
			return errors.New("exactly one of --project or --collection must be specified")
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
		if rateLimitFlag <= 0.0 {
			rateLimitFlag = 1000.0
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
			WitnessesPerMinute:      rateLimitFlag,
			Interfaces:              interfacesFlag,
			Filter:                  filterFlag,
			PathExclusions:          pathExclusionsFlag,
			HostExclusions:          hostExclusionsFlag,
			PathAllowlist:           pathAllowlistFlag,
			HostAllowlist:           hostAllowlistFlag,
			ExecCommand:             execCommandFlag,
			ExecCommandUser:         execCommandUserFlag,
			Plugins:                 plugins,
			LearnSessionLifetime:    traceRotateInterval,
			StatsLogDelay:           statsLogDelay,
			TelemetryInterval:       telemetryInterval,
			ProcFSPollingInterval:   procFSPollingInterval,
			CollectTCPAndTLSReports: collectTCPAndTLSReports,
			ParseTLSHandshakes:      parseTLSHandshakes,
			MaxWitnessSize_bytes:    maxWitnessSize_bytes,
			DockerExtensionMode:     dockerExtensionMode,
			HealthCheckPort:         healthCheckPort,
		}
		if err := apidump.Run(args); err != nil {
			return cmderr.AkitaErr{Err: err}
		}
		return nil
	},
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

	Cmd.Flags().StringVar(
		&filterFlag,
		"filter",
		"",
		"Used to match packets going to and coming from your API service.")

	Cmd.Flags().StringSliceVar(
		&interfacesFlag,
		"interfaces",
		nil,
		"List of network interfaces to listen on. Defaults to all interfaces on host.")

	Cmd.Flags().Float64Var(
		&sampleRateFlag,
		"sample-rate",
		1.0,
		"A number between [0.0, 1.0] to control sampling.",
	)
	Cmd.Flags().MarkDeprecated("sample-rate", "use --rate-limit instead.")

	Cmd.Flags().Float64Var(
		&rateLimitFlag,
		"rate-limit",
		apispec.DefaultRateLimit,
		"Number of requests per minute to capture.",
	)

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

	Cmd.Flags().StringSliceVar(
		&pathExclusionsFlag,
		"path-exclusions",
		nil,
		"Removes HTTP paths matching regular expressions.",
	)

	Cmd.Flags().StringSliceVar(
		&hostExclusionsFlag,
		"host-exclusions",
		nil,
		"Removes HTTP hosts matching regular expressions.",
	)

	Cmd.Flags().StringSliceVar(
		&pathAllowlistFlag,
		"path-allow",
		nil,
		"Allows only HTTP paths matching regular expressions.",
	)

	Cmd.Flags().StringSliceVar(
		&hostAllowlistFlag,
		"host-allow",
		nil,
		"Allows only HTTP hosts matching regular expressions.",
	)

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
		&statsLogDelay,
		"stats-log-delay",
		apispec.DefaultStatsLogDelay_seconds,
		"Print packet capture statistics after N seconds.",
	)

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
}
