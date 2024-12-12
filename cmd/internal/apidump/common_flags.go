package apidump

import (
	"strconv"

	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/spf13/cobra"
)

type CommonApidumpFlags struct {
	Filter              string
	HostAllowlist       []string
	HostExclusions      []string
	Interfaces          []string
	PathAllowlist       []string
	PathExclusions      []string
	RandomizedStart     int
	RateLimit           float64
	SendWitnessPayloads bool
}

func AddCommonApiDumpFlags(cmd *cobra.Command) *CommonApidumpFlags {
	flags := &CommonApidumpFlags{}

	cmd.Flags().StringVar(
		&flags.Filter,
		"filter",
		"",
		"Used to match packets going to and coming from your API service.",
	)

	cmd.Flags().StringSliceVar(
		&flags.HostAllowlist,
		"host-allow",
		nil,
		"Allows only HTTP hosts matching regular expressions.",
	)

	cmd.Flags().StringSliceVar(
		&flags.HostExclusions,
		"host-exclusions",
		nil,
		"Removes HTTP hosts matching regular expressions.",
	)

	cmd.Flags().StringSliceVar(
		&flags.Interfaces,
		"interfaces",
		nil,
		"List of network interfaces to listen on. Defaults to all interfaces on host.",
	)

	cmd.Flags().StringSliceVar(
		&flags.PathAllowlist,
		"path-allow",
		nil,
		"Allows only HTTP paths matching regular expressions.",
	)

	cmd.Flags().StringSliceVar(
		&flags.PathExclusions,
		"path-exclusions",
		nil,
		"Removes HTTP paths matching regular expressions.",
	)

	cmd.Flags().IntVar(
		&flags.RandomizedStart,
		"randomized-start",
		100,
		"Probability that the apidump command will start intercepting traffic.",
	)
	_ = cmd.Flags().MarkHidden("randomized-start")

	cmd.Flags().Float64Var(
		&flags.RateLimit,
		"rate-limit",
		apispec.DefaultRateLimit,
		"Number of requests per minute to capture.",
	)

	cmd.Flags().BoolVar(
		&flags.SendWitnessPayloads,
		"send-witness-payloads",
		false,
		"Send request and response payloads to Postman",
	)
	_ = cmd.Flags().MarkHidden("send-witness-payloads")

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

	if flags.RateLimit != apispec.DefaultRateLimit {
		commonApidumpArgs = append(commonApidumpArgs, "--rate-limit", strconv.FormatFloat(flags.RateLimit, 'f', -1, 64))
	}

	if flags.SendWitnessPayloads {
		commonApidumpArgs = append(commonApidumpArgs, "--send-witness-payloads")
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

	return commonApidumpArgs
}
