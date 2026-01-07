package data_masks

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/akid"
	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/test"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	mockrest "github.com/postmanlabs/postman-insights-agent/rest"
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

func TestRedaction(t *testing.T) {
	testCases := map[string]struct {
		agentConfig  optionals.Optional[*kgxapi.FieldRedactionConfig]
		inputFile    string
		expectedFile string
	}{
		// Expect values with 16-character identifiers to remain unchanged.
		"16-character identifier": {
			inputFile:    "002-witness.pb.txt",
			expectedFile: "002-witness.pb.txt",
		},

		"default redaction rules": {
			inputFile:    "003-witness.pb.txt",
			expectedFile: "003-expected-default-redaction.pb.txt",
		},

		"agent config: redact by name": {
			agentConfig: optionals.Some(&kgxapi.FieldRedactionConfig{
				FieldNames: []string{"by-name"},
			}),
			inputFile:    "003-witness.pb.txt",
			expectedFile: "003-expected-redact-by-name.pb.txt",
		},

		"agent config: redact by name regexp": {
			agentConfig: optionals.Some(&kgxapi.FieldRedactionConfig{
				FieldNameRegexps: []*regexp.Regexp{regexp.MustCompile("nam.*xp$")},
			}),
			inputFile:    "003-witness.pb.txt",
			expectedFile: "003-expected-redact-by-name-regexp.pb.txt",
		},

		"agent config: redact by name and by name regexp": {
			agentConfig: optionals.Some(&kgxapi.FieldRedactionConfig{
				FieldNames:       []string{"by-name"},
				FieldNameRegexps: []*regexp.Regexp{regexp.MustCompile("nam.*xp$")},
			}),
			inputFile:    "003-witness.pb.txt",
			expectedFile: "003-expected-redact-by-name-and-by-name-regexp.pb.txt",
		},

		"agent config: redact by name and by regexp": {
			agentConfig: optionals.Some(&kgxapi.FieldRedactionConfig{
				FieldNameRegexps: []*regexp.Regexp{regexp.MustCompile("^value for key[12]$")},
			}),
			inputFile:    "004-witness.pb.txt",
			expectedFile: "004-expected-redact-by-value-regexp.pb.txt",
		},
	}

	for testName, testCase := range testCases {
		func() {
			ctrl := gomock.NewController(t)
			mockClient := mockrest.NewMockLearnClient(ctrl)
			defer ctrl.Finish()

			agentConfig := kgxapi.NewServiceAgentConfig()
			if fieldsToRedact, exists := testCase.agentConfig.Get(); exists {
				agentConfig.FieldsToRedact = fieldsToRedact
			}

			mockClient.
				EXPECT().
				GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
				AnyTimes().
				Return(agentConfig, nil)

			o, err := NewRedactor(akid.GenerateServiceID(), mockClient)
			assert.NoError(t, err)

			testWitness := test.LoadWitnessFromFileOrDie(filepath.Join("testdata", testCase.inputFile))
			expectedWitness := test.LoadWitnessFromFileOrDie(filepath.Join("testdata", testCase.expectedFile))

			o.RedactSensitiveData(testWitness.Method)

			if diff := cmp.Diff(expectedWitness, testWitness, cmpOptions...); diff != "" {
				t.Errorf("found unexpected diff in test case %q:\n%s", testName, diff)
			}
		}()
	}
}

func TestZeroAllPrimitives(t *testing.T) {
	testCases := map[string]struct {
		agentConfig  optionals.Optional[*kgxapi.FieldRedactionConfig]
		inputFile    string
		expectedFile string
	}{
		"zero all primitives": {
			inputFile:    "001-witness.pb.txt",
			expectedFile: "001-expected-zero-all-primitives.pb.txt",
		},
		"redact secret in path": {
			inputFile:    "005-witness.pb.txt",
			expectedFile: "005-expected-redacted-path.pb.txt",
		},
		"preserve W3C trace context headers": {
			inputFile:    "006-witness-with-trace-context.pb.txt",
			expectedFile: "006-expected-zero-preserve-trace-context.pb.txt",
		},
		"preserve W3C trace context headers (case-insensitive)": {
			inputFile:    "007-witness-with-trace-context-mixed-case.pb.txt",
			expectedFile: "007-expected-zero-preserve-trace-context-mixed-case.pb.txt",
		},
	}

	for testName, testCase := range testCases {
		func() {
			ctrl := gomock.NewController(t)
			mockClient := mockrest.NewMockLearnClient(ctrl)
			defer ctrl.Finish()

			agentConfig := kgxapi.NewServiceAgentConfig()
			if fieldsToRedact, exists := testCase.agentConfig.Get(); exists {
				agentConfig.FieldsToRedact = fieldsToRedact
			}

			mockClient.
				EXPECT().
				GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
				AnyTimes().
				Return(agentConfig, nil)

			o, err := NewRedactor(akid.GenerateServiceID(), mockClient)
			assert.NoError(t, err)

			testWitness := test.LoadWitnessFromFileOrDie(filepath.Join("testdata", testCase.inputFile))
			expectedWitness := test.LoadWitnessFromFileOrDie(filepath.Join("testdata", testCase.expectedFile))

			o.ZeroAllPrimitives(testWitness.Method)

			if diff := cmp.Diff(expectedWitness, testWitness, cmpOptions...); diff != "" {
				t.Errorf("found unexpected diff in test case %q:\n%s", testName, diff)
			}
		}()
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

func BenchmarkZeroAllPrimitives(b *testing.B) {
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
		o.ZeroAllPrimitives(testWitness.Method)
	}
}
