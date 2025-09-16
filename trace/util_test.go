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

	result := shouldCapturePayload(witness, []*regexp.Regexp{regexp.MustCompile("/v1/chat/completions")})
	if !result {
		t.Errorf("shouldCapturePayload() = false, expected true for Postman internal team")
	}
}
