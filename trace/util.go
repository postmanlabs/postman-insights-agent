package trace

import (
	"regexp"
	"strings"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/http_rest_methods"
)

// Returns true if the witness should be excluded from Repro Mode.
//
// XXX This is a stop-gap hack to exclude certain endpoints for Cloud API from
// Repro Mode.
func excludeWitnessFromReproMode(method *pb.Method) bool {
	httpMeta := method.GetMeta().GetHttp()
	if httpMeta == nil {
		return false
	}

	if cloudAPIHostnames.Contains(strings.ToLower(httpMeta.Host)) {
		switch httpMeta.Method {
		case http_rest_methods.GET.String():
			// Exclude GET /environments/{environment}.
			if cloudAPIEnvironmentsPathRE.MatchString(httpMeta.PathTemplate) {
				return true
			}

		case http_rest_methods.POST.String():
			// Exclude POST /environments.
			if httpMeta.PathTemplate == "/environments" {
				return true
			}

		case http_rest_methods.PUT.String():
			// Exclude PUT /environments/{environment}.
			// Exclude GET /environments/{environment}.
			if cloudAPIEnvironmentsPathRE.MatchString(httpMeta.PathTemplate) {
				return true
			}
		}
	}
	return false
}

// Returns true if the witness path matches the always capture payloads regex.
func hasMatchingPath(witness *pb.Witness, alwaysCapturePayloadsPathsRegex []*regexp.Regexp) bool {
	for _, pathRE := range alwaysCapturePayloadsPathsRegex {
		if pathRE.MatchString(witness.GetMethod().GetMeta().GetHttp().GetPathTemplate()) {
			return true
		}
	}
	return false
}

// Determines whether a given method has only error (4xx or 5xx) response codes.
// Returns true if the method has at least one response and all response codes are 4xx or 5xx.
// Here method will only have single response object because in agent each witness stores single request-response pair.
func hasOnlyErrorResponses(method *pb.Method) bool {
	responses := method.GetResponses()
	if len(responses) == 0 {
		return false
	}

	for _, response := range responses {
		responseCode := response.Meta.GetHttp().GetResponseCode()
		if !(400 <= responseCode && responseCode < 600) {
			return false
		}
	}

	return true
}

// Returns true if the witness payload should be captured.
func shouldCapturePayload(witness *pb.Witness, alwaysCapturePayloadsPathsRegex []*regexp.Regexp) bool {
	// Step 1: Check if the witness should be excluded from Repro Mode.
	if excludeWitnessFromReproMode(witness.GetMethod()) {
		return false
	}

	// Step 2: Check if the method path matches the always capture payloads regex.
	if hasMatchingPath(witness, alwaysCapturePayloadsPathsRegex) {
		return true
	}

	// Step 3: Check if the method has only error responses.
	if hasOnlyErrorResponses(witness.GetMethod()) {
		return true
	}

	return false
}
