package trace

import (
	"regexp"
	"testing"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/spec_util"
)

func TestIsPostmanInternalTeam(t *testing.T) {
	tests := []struct {
		name     string
		witness  *pb.Witness
		expected bool
	}{
		{
			name: "Postman internal team with organization 1",
			witness: &pb.Witness{
				Method: &pb.Method{
					Args: map[string]*pb.Data{
						"test-key": {
							Value: &pb.Data_Primitive{
								Primitive: spec_util.NewPrimitiveString(`{"custom_postot_conversation_id":"12345678-1234-b1234-1234-123456789012","custom_postot_interaction_id":"12345678-1234-b1234-1234-123456789012","_prompt":"agent_system","_agent":"Root","_workflow":"agent_mode_chat","_domain":"agent_mode","_environment":"beta","_user":"916b323","_nrTraceId":"0d495a1379560f5d14f7f9c43d57bb07","_organization":"1"}`),
							},
							Meta: &pb.DataMeta{
								Meta: &pb.DataMeta_Http{
									Http: &pb.HTTPMeta{
										Location: &pb.HTTPMeta_Header{
											Header: &pb.HTTPHeader{
												Key: "x-portkey-metadata",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Non-Postman team with organization 2",
			witness: &pb.Witness{
				Method: &pb.Method{
					Args: map[string]*pb.Data{
						"test-key": {
							Value: &pb.Data_Primitive{
								Primitive: spec_util.NewPrimitiveString(`{"custom_postot_conversation_id":"12345678-1234-b1234-1234-123456789012","custom_postot_interaction_id":"12345678-1234-b1234-1234-123456789012","_prompt":"agent_system","_agent":"Root","_workflow":"agent_mode_chat","_domain":"agent_mode","_environment":"beta","_user":"916b323","_nrTraceId":"0d495a1379560f5d14f7f9c43d57bb07","_organization":"2"}`),
							},
							Meta: &pb.DataMeta{
								Meta: &pb.DataMeta_Http{
									Http: &pb.HTTPMeta{
										Location: &pb.HTTPMeta_Header{
											Header: &pb.HTTPHeader{
												Key: "x-portkey-metadata",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "No x-portkey-metadata header",
			witness: &pb.Witness{
				Method: &pb.Method{
					Args: map[string]*pb.Data{
						"test-key": {
							Value: &pb.Data_Primitive{
								Primitive: spec_util.NewPrimitiveString("some-other-header-value"),
							},
							Meta: &pb.DataMeta{
								Meta: &pb.DataMeta_Http{
									Http: &pb.HTTPMeta{
										Location: &pb.HTTPMeta_Header{
											Header: &pb.HTTPHeader{
												Key: "authorization",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Invalid JSON in x-portkey-metadata header",
			witness: &pb.Witness{
				Method: &pb.Method{
					Args: map[string]*pb.Data{
						"test-key": {
							Value: &pb.Data_Primitive{
								Primitive: spec_util.NewPrimitiveString("invalid-json"),
							},
							Meta: &pb.DataMeta{
								Meta: &pb.DataMeta_Http{
									Http: &pb.HTTPMeta{
										Location: &pb.HTTPMeta_Header{
											Header: &pb.HTTPHeader{
												Key: "x-portkey-metadata",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Empty witness",
			witness: &pb.Witness{
				Method: &pb.Method{
					Args: map[string]*pb.Data{},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPostmanInternalTeam(tt.witness)
			if result != tt.expected {
				t.Errorf("isPostmanInternalTeam() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestShouldCapturePayloadWithPostmanTeam(t *testing.T) {
	// Test that shouldCapturePayload returns true for Postman internal team
	witness := &pb.Witness{
		Method: &pb.Method{
			Meta: &pb.MethodMeta{
				Meta: &pb.MethodMeta_Http{
					Http: &pb.HTTPMethodMeta{
						Method:       "POST",
						PathTemplate: "/v1/chat/completions",
						Host:         "api.portkey.ai",
					},
				},
			},
			Args: map[string]*pb.Data{
				"test-key": {
					Value: &pb.Data_Primitive{
						Primitive: spec_util.NewPrimitiveString(`{"custom_postot_conversation_id":"12345678-1234-b1234-1234-123456789012","custom_postot_interaction_id":"12345678-1234-b1234-1234-123456789012","_prompt":"agent_system","_agent":"Root","_workflow":"agent_mode_chat","_domain":"agent_mode","_environment":"beta","_user":"916b323","_nrTraceId":"0d495a1379560f5d14f7f9c43d57bb07","_organization":"1"}`),
					},
					Meta: &pb.DataMeta{
						Meta: &pb.DataMeta_Http{
							Http: &pb.HTTPMeta{
								Location: &pb.HTTPMeta_Header{
									Header: &pb.HTTPHeader{
										Key: "x-portkey-metadata",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := shouldCapturePayload(witness, []*regexp.Regexp{regexp.MustCompile("/v1/chat/completions")}, false)
	if !result {
		t.Errorf("shouldCapturePayload() = false, expected true for Postman internal team")
	}
}

// Builds a witness for a plain, non-Cloud-API endpoint with the given response
// code and no always-capture headers.
func witnessWithResponseCode(code int32) *pb.Witness {
	return &pb.Witness{
		Method: &pb.Method{
			Meta: &pb.MethodMeta{
				Meta: &pb.MethodMeta_Http{
					Http: &pb.HTTPMethodMeta{
						Method:       "GET",
						PathTemplate: "/v1/users/{id}",
						Host:         "api.example.com",
					},
				},
			},
			Responses: map[string]*pb.Data{
				"response": {
					Meta: &pb.DataMeta{
						Meta: &pb.DataMeta_Http{
							Http: &pb.HTTPMeta{
								ResponseCode: code,
							},
						},
					},
				},
			},
		},
	}
}

func TestShouldCapturePayloadRecordAll(t *testing.T) {
	tests := []struct {
		name      string
		code      int32
		recordAll bool
		expected  bool
	}{
		{"success without record-all is not captured", 200, false, false},
		{"success with record-all is captured", 200, true, true},
		{"client error is captured without record-all", 404, false, true},
		{"server error is captured without record-all", 500, false, true},
		{"client error still captured with record-all", 404, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldCapturePayload(witnessWithResponseCode(tt.code), nil, tt.recordAll)
			if result != tt.expected {
				t.Errorf("shouldCapturePayload() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// record-all must not override the Cloud API exclusions, which exist to keep
// environment secrets out of Repro Mode entirely.
func TestShouldCapturePayloadRecordAllRespectsExclusions(t *testing.T) {
	witness := &pb.Witness{
		Method: &pb.Method{
			Meta: &pb.MethodMeta{
				Meta: &pb.MethodMeta_Http{
					Http: &pb.HTTPMethodMeta{
						Method:       "GET",
						PathTemplate: "/environments/{environment}",
						Host:         "api.getpostman.com",
					},
				},
			},
			Responses: map[string]*pb.Data{
				"response": {
					Meta: &pb.DataMeta{
						Meta: &pb.DataMeta_Http{
							Http: &pb.HTTPMeta{
								ResponseCode: 200,
							},
						},
					},
				},
			},
		},
	}

	if shouldCapturePayload(witness, nil, true) {
		t.Errorf("shouldCapturePayload() = true, expected false for an excluded Cloud API path even with record-all")
	}
}

// record-all must not override the Postman-internal-team check either: an
// always-capture path belonging to another team stays out of Repro Mode, since
// that check exists because we are not allowed to capture those payloads on
// Portkey production.
func TestShouldCapturePayloadRecordAllRespectsPostmanTeamCheck(t *testing.T) {
	// Same always-capture path as TestShouldCapturePayloadWithPostmanTeam, but
	// with an organization that is not the internal team for its environment.
	witness := &pb.Witness{
		Method: &pb.Method{
			Meta: &pb.MethodMeta{
				Meta: &pb.MethodMeta_Http{
					Http: &pb.HTTPMethodMeta{
						Method:       "POST",
						PathTemplate: "/v1/chat/completions",
						Host:         "api.portkey.ai",
					},
				},
			},
			Args: map[string]*pb.Data{
				"test-key": {
					Value: &pb.Data_Primitive{
						Primitive: spec_util.NewPrimitiveString(`{"_environment":"production","_organization":"999999"}`),
					},
					Meta: &pb.DataMeta{
						Meta: &pb.DataMeta_Http{
							Http: &pb.HTTPMeta{
								Location: &pb.HTTPMeta_Header{
									Header: &pb.HTTPHeader{
										Key: "x-portkey-metadata",
									},
								},
							},
						},
					},
				},
			},
			Responses: map[string]*pb.Data{
				"response": {
					Meta: &pb.DataMeta{
						Meta: &pb.DataMeta_Http{
							Http: &pb.HTTPMeta{
								ResponseCode: 200,
							},
						},
					},
				},
			},
		},
	}

	alwaysCapture := []*regexp.Regexp{regexp.MustCompile("/v1/chat/completions")}
	if shouldCapturePayload(witness, alwaysCapture, true) {
		t.Errorf("shouldCapturePayload() = true, expected false for a non-internal team on an always-capture path even with record-all")
	}

	// With no always-capture paths configured, record-all captures it as normal.
	if !shouldCapturePayload(witness, nil, true) {
		t.Errorf("shouldCapturePayload() = false, expected true with record-all and no always-capture paths")
	}
}
