package apidump

import (
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

type CommonApidumpFlags struct {
	Filter                string
	HostAllowlist         []string
	HostExclusions        []string
	Interfaces            []string
	PathAllowlist         []string
	PathExclusions        []string
	RandomizedStart       int
	RateLimit             float64
	SendWitnessPayloads   bool
	EnableReproMode       bool
	AlwaysCapturePayloads []string
	RecordAll             bool
	CaptureWindow         time.Duration
	CaptureEvery          time.Duration
	RecordAllHosts        []string
	RecordAllPaths        []string
}

func AddCommonApiDumpFlags(cmd *cobra.Command) *CommonApidumpFlags {
	flags := &CommonApidumpFlags{}

	cmd.PersistentFlags().StringVar(
		&flags.Filter,
		"filter",
		"",
		"Used to match packets going to and coming from your API service.",
	)

	cmd.PersistentFlags().StringSliceVar(
		&flags.HostAllowlist,
		"host-allow",
		nil,
		"Allows only HTTP hosts matching regular expressions.",
	)

	cmd.PersistentFlags().StringSliceVar(
		&flags.HostExclusions,
		"host-exclusions",
		nil,
		"Removes HTTP hosts matching regular expressions.",
	)

	cmd.PersistentFlags().StringSliceVar(
		&flags.Interfaces,
		"interfaces",
		nil,
		"List of network interfaces to listen on. Defaults to all interfaces on host.",
	)

	cmd.PersistentFlags().StringSliceVar(
		&flags.PathAllowlist,
		"path-allow",
		nil,
		"Allows only HTTP paths matching regular expressions.",
	)

	cmd.PersistentFlags().StringSliceVar(
		&flags.PathExclusions,
		"path-exclusions",
		nil,
		"Removes HTTP paths matching regular expressions.",
	)

	cmd.PersistentFlags().IntVar(
		&flags.RandomizedStart,
		"randomized-start",
		100,
		"Probability that the apidump command will start intercepting traffic.",
	)
	_ = cmd.PersistentFlags().MarkHidden("randomized-start")

	cmd.PersistentFlags().Float64Var(
		&flags.RateLimit,
		"rate-limit",
		0.0,
		"Number of requests per minute to capture.",
	)

	cmd.PersistentFlags().BoolVar(
		&flags.SendWitnessPayloads,
		"send-witness-payloads",
		false,
		"Send request and response payloads to Postman",
	)
	_ = cmd.PersistentFlags().MarkHidden("send-witness-payloads")

	cmd.PersistentFlags().BoolVar(
		&flags.EnableReproMode,
		"repro-mode",
		false,
		"Enable repro mode to send request and response payloads to Postman.",
	)

	cmd.PersistentFlags().StringSliceVar(
		&flags.AlwaysCapturePayloads,
		"always-capture-payloads",
		nil,
		"Always capture request and response payloads for the given paths.",
	)
	_ = cmd.PersistentFlags().MarkHidden("always-capture-payloads")

	cmd.PersistentFlags().BoolVar(
		&flags.RecordAll,
		"record-all",
		false,
		"Send request and response payloads for all responses, not just errors. Implies --repro-mode.",
	)
	_ = cmd.PersistentFlags().MarkHidden("record-all")

	cmd.PersistentFlags().DurationVar(
		&flags.CaptureWindow,
		"capture-window",
		0,
		"How long --record-all payload capture stays on, e.g. 15m. Zero keeps it on for the agent's lifetime.",
	)
	_ = cmd.PersistentFlags().MarkHidden("capture-window")

	cmd.PersistentFlags().DurationVar(
		&flags.CaptureEvery,
		"capture-every",
		0,
		"How often the --capture-window reopens, e.g. 24h. Zero captures one window and stops.",
	)
	_ = cmd.PersistentFlags().MarkHidden("capture-every")

	// StringArrayVar, not StringSliceVar: pflag runs a slice value through
	// encoding/csv, which splits a regex on its commas. `[0-9a-f]{8,}` becomes
	// `[0-9a-f]{8` and `}$` -- both of which compile, neither of which matches
	// anything, so record-all would report itself as scoped and capture nothing.
	cmd.PersistentFlags().StringArrayVar(
		&flags.RecordAllHosts,
		"record-all-hosts",
		nil,
		"Restrict --record-all to hosts matching these regexes. Empty means every host.",
	)
	_ = cmd.PersistentFlags().MarkHidden("record-all-hosts")

	// StringArrayVar for the same reason as --record-all-hosts above.
	cmd.PersistentFlags().StringArrayVar(
		&flags.RecordAllPaths,
		"record-all-paths",
		nil,
		"Restrict --record-all to request paths matching these regexes. Empty means every path.",
	)
	_ = cmd.PersistentFlags().MarkHidden("record-all-paths")

	return flags
}

func ConvertCommonApiDumpFlagsToArgs(flags *CommonApidumpFlags) []string {
	commonApidumpArgs := []string{}

	if flags.Filter != "" {
		commonApidumpArgs = append(commonApidumpArgs, "--filter", flags.Filter)
	}

	if flags.RandomizedStart != 100 {
		commonApidumpArgs = append(commonApidumpArgs, "--randomized-start", strconv.Itoa(flags.RandomizedStart))
	}

	if flags.RateLimit != 0.0 {
		commonApidumpArgs = append(commonApidumpArgs, "--rate-limit", strconv.FormatFloat(flags.RateLimit, 'f', -1, 64))
	}

	if flags.SendWitnessPayloads {
		commonApidumpArgs = append(commonApidumpArgs, "--send-witness-payloads")
	}

	if flags.EnableReproMode {
		commonApidumpArgs = append(commonApidumpArgs, "--repro-mode")
	}

	if flags.RecordAll {
		commonApidumpArgs = append(commonApidumpArgs, "--record-all")
	}

	if flags.CaptureWindow != 0 {
		commonApidumpArgs = append(commonApidumpArgs, "--capture-window", flags.CaptureWindow.String())
	}

	if flags.CaptureEvery != 0 {
		commonApidumpArgs = append(commonApidumpArgs, "--capture-every", flags.CaptureEvery.String())
	}

	for _, host := range flags.RecordAllHosts {
		commonApidumpArgs = append(commonApidumpArgs, "--record-all-hosts", host)
	}

	for _, path := range flags.RecordAllPaths {
		commonApidumpArgs = append(commonApidumpArgs, "--record-all-paths", path)
	}

	// Add slice type flags to the entry point.
	// Flags: --host-allow, --host-exclusions, --interfaces, --path-allow, --path-exclusions
	// Added them separately instead of joining with comma(,) to avoid any regex parsing issues.
	for _, host := range flags.HostAllowlist {
		commonApidumpArgs = append(commonApidumpArgs, "--host-allow", host)
	}
	for _, host := range flags.HostExclusions {
		commonApidumpArgs = append(commonApidumpArgs, "--host-exclusions", host)
	}
	for _, interfaceFlag := range flags.Interfaces {
		commonApidumpArgs = append(commonApidumpArgs, "--interfaces", interfaceFlag)
	}
	for _, path := range flags.PathAllowlist {
		commonApidumpArgs = append(commonApidumpArgs, "--path-allow", path)
	}
	for _, path := range flags.PathExclusions {
		commonApidumpArgs = append(commonApidumpArgs, "--path-exclusions", path)
	}
	for _, path := range flags.AlwaysCapturePayloads {
		commonApidumpArgs = append(commonApidumpArgs, "--always-capture-payloads", path)
	}

	return commonApidumpArgs
}
