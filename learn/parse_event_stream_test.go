package learn

import (
	"strings"
	"testing"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/spec_util"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
)

func TestParseEventStream(t *testing.T) {
	testCases := []struct {
		name         string
		testContent  string
		expectedData *pb.Data
	}{
		{
			name:        "single event",
			testContent: "event: myEvent\ndata: myData\nid: 12345\nretry: 20000\n\n",
			expectedData: dataFromList(
				dataFromStruct(map[string]*pb.Data{
					"event": dataFromPrimitive(spec_util.NewPrimitiveString("myEvent")),
					"data":  dataFromPrimitive(spec_util.NewPrimitiveString("myData")),
					"id":    dataFromPrimitive(spec_util.NewPrimitiveString("12345")),
					"retry": dataFromPrimitive(spec_util.NewPrimitiveString("20000")),
				}),
			),
		},
		{
			name:        "multi-line data",
			testContent: "data: line1\ndata: line2\r\ndata: line3\n\n",
			expectedData: dataFromList(
				dataFromStruct(map[string]*pb.Data{
					"data": dataFromPrimitive(spec_util.NewPrimitiveString("line1\nline2\nline3")),
				}),
			),
		},
		{
			name:        "JSON data",
			testContent: "data: {\"aaa\": 123, \"bbb\": \"456\"}\n\n",
			expectedData: dataFromList(
				dataFromStruct(map[string]*pb.Data{
					"data": dataFromStruct(map[string]*pb.Data{
						"aaa": dataFromPrimitive(spec_util.NewPrimitiveInt64(123)),
						"bbb": dataFromPrimitive(spec_util.NewPrimitiveString("456")),
					}),
				}),
			),
		},
		{
			name:        "JSON data with type and comment",
			testContent: "event: testEvent\n:this is a comment\ndata: {\"aaa\": 123, \"bbb\": \"456\"}\n\n",
			expectedData: dataFromList(
				dataFromStruct(map[string]*pb.Data{
					"event": dataFromPrimitive(spec_util.NewPrimitiveString("testEvent")),
					"data": dataFromStruct(map[string]*pb.Data{
						"aaa": dataFromPrimitive(spec_util.NewPrimitiveInt64(123)),
						"bbb": dataFromPrimitive(spec_util.NewPrimitiveString("456")),
					}),
				}),
			),
		},
		{
			name:        "extra spaces in data",
			testContent: "data:  foo\n\n",
			expectedData: dataFromList(
				dataFromStruct(map[string]*pb.Data{
					"data": dataFromPrimitive(spec_util.NewPrimitiveString(" foo")),
				}),
			),
		},
		// FIXME: should we fill in "data" with an empty string?
		{
			name:        "nonstandard field name and empty data",
			testContent: ":\nevent: testEvent\n:comment\nfieldName:fieldValue\n\n",
			expectedData: dataFromList(
				dataFromStruct(map[string]*pb.Data{
					"event": dataFromPrimitive(spec_util.NewPrimitiveString("testEvent")),
				}),
			),
		},
		// This is an ambiguous case we can't handle correctly in the Akita IR
		{
			name:        "quoted string",
			testContent: "data: \"aaa\"\n\n",
			expectedData: dataFromList(
				dataFromStruct(map[string]*pb.Data{
					"data": dataFromPrimitive(spec_util.NewPrimitiveString("aaa")),
				}),
			),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualData, err := parseEventStream(strings.NewReader(tc.testContent))
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.expectedData, actualData, cmp.Comparer(proto.Equal)); diff != "" {
				t.Fatalf("Diff failed:\n%v", diff)
			}
		})
	}
}
