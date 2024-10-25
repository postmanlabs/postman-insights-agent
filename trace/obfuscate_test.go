package trace

import (
	"testing"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/spec_util"
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

func BenchmarkRedaction(b *testing.B) {
	o := NewObfuscator()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		o.RedactData(testWitness.Method)
	}
}

func BenchmarkObfuscation(b *testing.B) {
	o := NewObfuscator()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		o.ObfuscateDataWithZeroValue(testWitness.Method)
	}
}
