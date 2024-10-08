package trace

import pb "github.com/akitasoftware/akita-ir/go/api_spec"

// Determines whether a given method has error (4xx or 5xx) response codes. Returns true if the method has at least one response and all response codes are 4xx or 5xx.
// Here method will only have single response object because in agent each witness stores single request-response pair.
func hasErrorResponses(method *pb.Method) bool {
	responses := method.GetResponses()
	if len(responses) == 0 {
		return false
	}

	for _, response := range responses {
		responseCode := response.Meta.GetHttp().GetResponseCode()
		if responseCode < 400 {
			return false
		}
	}

	return true
}
