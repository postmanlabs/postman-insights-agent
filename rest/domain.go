package rest

import (
	"strings"

	"github.com/postmanlabs/postman-insights-agent/cfg"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

const (
	RegionUS = "US"
	RegionEU = "EU"
)

// Domain is the backend host (or host:port) to use. When empty, DefaultDomain() runs before use.
//
// Resolution order: --domain wins if set; otherwise host comes from region (--region /
// POSTMAN_REGION / credentials) plus POSTMAN_ENV, same as historical US behavior.
var Domain string

// Region is the --region flag; empty means use cfg.PostmanRegion() / POSTMAN_REGION.
var Region string

// EffectivePostmanRegion returns US or EU (default US).
func EffectivePostmanRegion() string {
	r := strings.TrimSpace(Region)
	if r == "" {
		r = cfg.PostmanRegion()
	}
	if r == "" {
		return RegionUS
	}
	switch strings.ToUpper(r) {
	case RegionUS:
		return RegionUS
	case RegionEU:
		return RegionEU
	default:
		printer.Warningf("Unknown region %q, using %s.\n", r, RegionUS)
		return RegionUS
	}
}

// DefaultDomain returns the observability API host for the current region and POSTMAN_ENV.
func DefaultDomain() string {
	_, env := cfg.GetPostmanAPIKeyAndEnvironment()
	return defaultObservabilityHost(EffectivePostmanRegion(), env)
}

func defaultObservabilityHost(region, env string) string {
	u := strings.ToUpper(strings.TrimSpace(env))
	if region == RegionEU {
		return euObservabilityHost(u, env)
	}
	return usObservabilityHost(u, env)
}

func euObservabilityHost(envUpper, envRaw string) string {
	switch envUpper {
	case "ALPHA":
		printer.Debugf("Selecting Postman EU alpha backend.\n")
		return "api.observability.eu.postman-alphta.com"
	case "", "PRODUCTION":
		printer.Debugf("Selecting Postman EU production backend.\n")
		return "api.observability.eu.postman.com"
	default:
		printer.Warningf("Unknown Postman environment %q for EU region; using EU production.\n", envRaw)
		return "api.observability.eu.postman.com"
	}
}

func usObservabilityHost(envUpper, envRaw string) string {
	switch envUpper {
	case "":
		// Not specified by user, default to PRODUCTION
		return "api.observability.postman.com"
	case "DEV":
		printer.Debugf("Selecting localhost backend for DEV environment.\n")
		return "localhost:50443"
	case "BETA":
		printer.Debugf("Selecting Postman beta backend for pre-production testing.\n")
		return "api.observability.postman-beta.com"
	case "PREVIEW":
		printer.Debugf("Selecting Postman preview backend for pre-production testing.\n")
		return "api.observability.postman-preview.com"
	case "STAGE":
		printer.Debugf("Selecting Postman staging backend for pre-production testing.\n")
		return "api.observability.postman-stage.com"
	case "PRODUCTION":
		printer.Debugf("Selecting Postman production backend.\n")
		return "api.observability.postman.com"
	default:
		printer.Warningf("Unknown Postman environment %q, using production.\n", envRaw)
		return "api.observability.postman.com"
	}
}
