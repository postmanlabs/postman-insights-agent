package data_masks

import (
	"path/filepath"
	"testing"

	"github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/akid"
	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/test"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	mockrest "github.com/postmanlabs/postman-insights-agent/rest/mock"
	"github.com/stretchr/testify/assert"
)

var cmpOptions = []cmp.Option{
	cmp.Comparer(proto.Equal),
	cmpopts.SortSlices(sortMethod),
	cmpopts.SortSlices(sortWitness),
}

func sortMethod(m1, m2 *api_spec.Method) bool {
	return proto.MarshalTextString(m1) < proto.MarshalTextString(m2)
}

func sortWitness(m1, m2 *api_spec.Witness) bool {
	return proto.MarshalTextString(m1) < proto.MarshalTextString(m2)
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

	testWitness := test.LoadWitnessFromFileOrDie(filepath.Join("testdata", "002-witness.pb.txt"))
	expectedWitness := test.LoadWitnessFromFileOrDie(filepath.Join("testdata", "002-witness.pb.txt"))

	o.RedactSensitiveData(testWitness.Method)

	// Expect witness to remain unchanged.
	if diff := cmp.Diff(expectedWitness, testWitness, cmpOptions...); diff != "" {
		t.Errorf("found diff:\n%s", diff)
	}
}

func BenchmarkRedaction(b *testing.B) {
	ctrl := gomock.NewController(b)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()

	mockClient.
		EXPECT().
		GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(kgxapi.NewServiceAgentConfig(), nil)

	o, err := NewRedactor(akid.GenerateServiceID(), mockClient)
	assert.NoError(b, err)

	testWitness := test.LoadWitnessFromFileOrDie(filepath.Join("testdata", "001-witness.pb.txt"))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		o.RedactSensitiveData(testWitness.Method)
	}
}
