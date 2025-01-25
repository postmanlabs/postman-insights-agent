package data_masks

import (
	"testing"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/akid"
	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/spec_util"
	"github.com/golang/mock/gomock"
	mockrest "github.com/postmanlabs/postman-insights-agent/rest/mock"
	"github.com/postmanlabs/postman-insights-agent/test_utils"
	"github.com/stretchr/testify/assert"
)

var (
	dataFromList              = test_utils.DataFromList
	dataFromPrimitive         = test_utils.DataFromPrimitive
	newTestBodySpecFromStruct = test_utils.NewTestBodySpecFromStruct
	newTestHeaderSpec         = test_utils.NewTestHeaderSpec
)

var testWitness *pb.Witness = &pb.Witness{
	Method: &pb.Method{
		Id: &pb.MethodID{
			ApiType: pb.ApiType_HTTP_REST,
		},
		Args: map[string]*pb.Data{
			"KC2RO-pCNJA=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString("Normal-Value")), "Normal-Header", 0),
			"4F1vWo8G_-Q=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString("SECRET")), "x-access-token", 0),
			"MWeG2T99uHI=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
				"name":         dataFromPrimitive(spec_util.NewPrimitiveString("error")),
				"number":       dataFromPrimitive(spec_util.NewPrimitiveInt64(202410081550)),
				"secret-value": dataFromPrimitive(spec_util.NewPrimitiveString("000000000000000|aaaaaaaaaaaaaaaaaaaaaaaaaaa")),
			}),
		},
		Responses: map[string]*pb.Data{
			"T7Jfr4mf1Zs=": newTestBodySpecFromStruct(404, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
				"homes": dataFromList(
					dataFromPrimitive(spec_util.NewPrimitiveString("error")),
					dataFromPrimitive(spec_util.NewPrimitiveString("happened")),
					dataFromPrimitive(spec_util.NewPrimitiveString("here")),
				),
			}),
		},
		Meta: &pb.MethodMeta{
			Meta: &pb.MethodMeta_Http{
				Http: &pb.HTTPMethodMeta{
					Method:       "POST",
					PathTemplate: "/v1/doggos",
					Host:         "example.com",
				},
			},
		},
	},
}

func TestRedaction16CharacterIdentifier(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()

	mockClient.
		EXPECT().
		GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(kgxapi.NewServiceAgentConfig(), nil)

	o, err := NewRedactor(akid.GenerateServiceID(), mockClient)
	assert.NoError(t, err)

	origVal1 := "aaaaaaaaaaaaaaaa"
	origVal2 := "0123456789012345"

	witness := &pb.Witness{
		Method: &pb.Method{
			Id: &pb.MethodID{
				ApiType: pb.ApiType_HTTP_REST,
			},
			Args: map[string]*pb.Data{
				"1": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString(origVal1)), "Normal-Header", 0),
				"2": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString(origVal2)), "Totally-Innocent", 0),
			},
			Responses: map[string]*pb.Data{},
			Meta: &pb.MethodMeta{
				Meta: &pb.MethodMeta_Http{
					Http: &pb.HTTPMethodMeta{
						Method:       "POST",
						PathTemplate: "/v1/doggos",
						Host:         "example.com",
					},
				},
			},
		},
	}

	o.RedactSensitiveData(witness.Method)

	assert.Equal(t, origVal1, witness.Method.Args["1"].GetPrimitive().GetStringValue().Value)
	assert.Equal(t, origVal2, witness.Method.Args["2"].GetPrimitive().GetStringValue().Value)
}

func BenchmarkRedaction(b *testing.B) {
	o, err := NewRedactor(akid.GenerateServiceID(), nil)
	assert.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		o.RedactSensitiveData(testWitness.Method)
	}
}
