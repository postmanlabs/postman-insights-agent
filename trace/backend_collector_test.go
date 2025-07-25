package trace

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/batcher"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/akitasoftware/akita-libs/spec_util"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/postmanlabs/postman-insights-agent/apispec"
	"github.com/postmanlabs/postman-insights-agent/data_masks"
	mockrest "github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/stretchr/testify/assert"
)

var (
	fakeSvc = akid.NewServiceID(uuid.Must(uuid.Parse("8b2cf196-87fe-4e53-a6b9-1452d7efb863")))
	fakeLrn = akid.NewLearnSessionID(uuid.Must(uuid.Parse("2b5dd735-9fc0-4365-93e8-74bf86d3f853")))
)

var redactionString = data_masks.RedactionString

type witnessRecorder struct {
	witnesses chan *pb.Witness
}

func newWitnessRecorder() *witnessRecorder {
	return &witnessRecorder{
		witnesses: make(chan *pb.Witness, 100), // making the channel size large to prevent dead-locking the main test co-routine
	}
}

// Record a call to LearnClient.AsyncReportsUpload
func (wr *witnessRecorder) recordAsyncReportsUpload(args ...interface{}) {
	reports := args[2].(*kgxapi.UploadReportsRequest)
	for _, r := range reports.Witnesses {
		bs, err := base64.URLEncoding.DecodeString(r.WitnessProto)
		if err != nil {
			panic(err)
		}

		w := &pb.Witness{}
		if err := proto.Unmarshal(bs, w); err != nil {
			panic(err)
		}
		wr.witnesses <- w
	}
}

func (wr *witnessRecorder) assertExpectedWitnesses(t *testing.T, expectedWitnesses []*pb.Witness) {
	for i := range expectedWitnesses {
		expected := proto.MarshalTextString(expectedWitnesses[i])
		actual := proto.MarshalTextString(<-wr.witnesses)
		assert.Equal(t, expected, actual)
	}
}

func (wr *witnessRecorder) assertExpectedWitnessLatency(t *testing.T, expectedWitnesses int, expectedLatencies []float32) {
	witnesses := make([]*pb.Witness, 0)
	for range expectedWitnesses {
		witnesses = append(witnesses, <-wr.witnesses)
	}
	assert.Equal(t, expectedWitnesses, len(witnesses))
	for i, expectedLatency := range expectedLatencies {
		witness := witnesses[i]
		meta := spec_util.HTTPMetaFromMethod(witness.Method)
		assert.NotNil(t, meta)
		assert.InDelta(t, expectedLatency, meta.ProcessingLatency, 0.001)
	}
}

// Make sure we redact values before uploading.
func TestRedact(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()

	rec := newWitnessRecorder()
	mockClient.
		EXPECT().
		AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(rec.recordAsyncReportsUpload).
		AnyTimes().
		Return(nil)

	mockClient.
		EXPECT().
		GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(kgxapi.NewServiceAgentConfig(), nil)

	streamID := uuid.New()
	req := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPRequest{
			StreamID: streamID,
			Seq:      1203,
			Method:   "POST",
			URL: &url.URL{
				Path: "/v1/doggos",
			},
			Host: "example.com",
			Header: map[string][]string{
				"Content-Type": {"application/json"},
			},
			Body: memview.New([]byte(`{"name": "prince", "number": 6119717375543385000}`)),
		},
	}

	resp := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPResponse{
			StreamID:   streamID,
			Seq:        1203,
			StatusCode: 200,
			Header: map[string][]string{
				"Content-Type": {"application/json"},
			},
			Body: memview.New([]byte(`{"homes": ["burbank, ca", "jeuno, ak", "versailles"]}`)),
		},
	}

	redactor, err := data_masks.NewRedactor(fakeSvc, mockClient)
	assert.NoError(t, err)

	col := NewBackendCollector(
		fakeSvc,
		map[tags.Key]string{},
		fakeLrn,
		mockClient,
		redactor,
		optionals.None[int](),
		NewPacketCounter(),
		false,
		nil,
		apispec.DefaultMaxWintessUploadBuffers,
	)
	assert.NoError(t, col.Process(req))
	assert.NoError(t, col.Process(resp))
	assert.NoError(t, col.Close())

	expectedWitnesses := []*pb.Witness{
		{
			Method: &pb.Method{
				Id: &pb.MethodID{
					ApiType: pb.ApiType_HTTP_REST,
				},
				Args: map[string]*pb.Data{
					"nxnOc5Qy3D4=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
						"name":   dataFromPrimitive(spec_util.NewPrimitiveString("")),
						"number": dataFromPrimitive(spec_util.NewPrimitiveInt64(0)),
					}),
				},
				Responses: map[string]*pb.Data{
					"AyBUQkT0SHU=": newTestBodySpecFromStruct(200, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
						"homes": dataFromList(
							dataFromPrimitive(spec_util.NewPrimitiveString("")),
							dataFromPrimitive(spec_util.NewPrimitiveString("")),
							dataFromPrimitive(spec_util.NewPrimitiveString("")),
						),
					}),
				},
				Meta: &pb.MethodMeta{
					Meta: &pb.MethodMeta_Http{
						Http: &pb.HTTPMethodMeta{
							Method:       "POST",
							PathTemplate: "/v1/doggos",
							Host:         "example.com",
							Obfuscation:  pb.HTTPMethodMeta_ZERO_VALUE,
						},
					},
				},
			},
		},
	}

	rec.assertExpectedWitnesses(t, expectedWitnesses)
}

func dataFromPrimitive(p *pb.Primitive) *pb.Data {
	return &pb.Data{Value: &pb.Data_Primitive{Primitive: p}}
}

func dataFromStruct(fields map[string]*pb.Data) *pb.Data {
	return &pb.Data{Value: &pb.Data_Struct{Struct: &pb.Struct{Fields: fields}}}
}

func dataFromList(elems ...*pb.Data) *pb.Data {
	return &pb.Data{Value: &pb.Data_List{List: &pb.List{Elems: elems}}}
}

func newTestBodySpecFromStruct(statusCode int, contentType pb.HTTPBody_ContentType, originalContentType string, s map[string]*pb.Data) *pb.Data {
	return newTestBodySpecFromData(statusCode, contentType, originalContentType, dataFromStruct(s))
}

func newTestBodySpecFromData(statusCode int, contentType pb.HTTPBody_ContentType, originalContentType string, d *pb.Data) *pb.Data {
	d.Meta = newBodyDataMeta(statusCode, contentType, originalContentType)
	return d
}

func newTestMultipartFormDataSpec(responseCode int, d *pb.Data) *pb.Data {
	d.Meta = newDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Multipart{
			Multipart: &pb.HTTPMultipart{
				Type: "form-data",
			},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}

func newBodyDataMeta(responseCode int, contentType pb.HTTPBody_ContentType, originalContentType string) *pb.DataMeta {
	return newDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Body{
			Body: &pb.HTTPBody{
				ContentType: contentType,
				OtherType:   originalContentType,
			},
		},
		ResponseCode: int32(responseCode),
	})
}

func newDataMeta(httpM *pb.HTTPMeta) *pb.DataMeta {
	return &pb.DataMeta{
		Meta: &pb.DataMeta_Http{
			Http: httpM,
		},
	}
}

func newTestHeaderSpec(d *pb.Data, key string, responseCode int) *pb.Data {
	d.Meta = newDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Header{
			Header: &pb.HTTPHeader{
				Key: key,
			},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}

func newTestQueryParamSpec(d *pb.Data, key string, responseCode int) *pb.Data {
	d.Meta = newDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Query{
			Query: &pb.HTTPQuery{
				Key: key,
			},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}

func newTestAuthSpec(d *pb.Data, responseCode int) *pb.Data {
	d.Meta = newDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Auth{
			Auth: &pb.HTTPAuth{},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}

func newTestCookieSpec(d *pb.Data, key string, responseCode int) *pb.Data {
	d.Meta = newDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Cookie{
			Cookie: &pb.HTTPCookie{
				Key: key,
			},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}

// Verify processing latency computation
func TestTiming(t *testing.T) {
	streamID := uuid.New()
	seq := 1023
	startTime := time.Now()

	request := func(streamID uuid.UUID, seq int, observationTime, finalPacketTime time.Time) akinet.ParsedNetworkTraffic {
		return akinet.ParsedNetworkTraffic{
			Content: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      seq,
				Method:   "GET",
				URL: &url.URL{
					Path: "/v1/doggos",
				},
				Host: "example.com",
			},
			ObservationTime: observationTime,
			FinalPacketTime: finalPacketTime,
		}
	}
	response := func(streamID uuid.UUID, seq int, observationTime, finalPacketTime time.Time) akinet.ParsedNetworkTraffic {
		return akinet.ParsedNetworkTraffic{
			Content: akinet.HTTPResponse{
				StreamID:   streamID,
				Seq:        seq,
				StatusCode: 200,
			},
			ObservationTime: observationTime,
			FinalPacketTime: finalPacketTime,
		}
	}

	cases := []struct {
		Name              string
		PNTs              []akinet.ParsedNetworkTraffic
		ExpectedWitnesses int
		ExpectedLatencies []float32
	}{
		{
			Name: "request + response 8 ms appart",
			PNTs: []akinet.ParsedNetworkTraffic{
				request(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
				response(streamID, seq, startTime.Add(10*time.Millisecond), startTime.Add(13*time.Millisecond)),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{8.0},
		},
		{
			Name: "response + request 8 ms appart",
			PNTs: []akinet.ParsedNetworkTraffic{
				response(streamID, seq, startTime.Add(10*time.Millisecond), startTime.Add(13*time.Millisecond)),
				request(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{8.0},
		},
		{
			Name: "request + response 0 ms appart",
			PNTs: []akinet.ParsedNetworkTraffic{
				request(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
				response(streamID, seq, startTime.Add(2*time.Millisecond), startTime.Add(13*time.Millisecond)),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{0.0},
		},
		{
			Name: "response + request 0 ms appart",
			PNTs: []akinet.ParsedNetworkTraffic{
				response(streamID, seq, startTime.Add(2*time.Millisecond), startTime.Add(13*time.Millisecond)),
				request(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{0.0},
		},
		{
			Name: "request + response 1 ms overlap",
			PNTs: []akinet.ParsedNetworkTraffic{
				request(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
				response(streamID, seq, startTime.Add(1*time.Millisecond), startTime.Add(3*time.Millisecond)),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{-1.0},
		},
		{
			Name: "response + request 1 ms overlap",
			PNTs: []akinet.ParsedNetworkTraffic{
				response(streamID, seq, startTime.Add(1*time.Millisecond), startTime.Add(3*time.Millisecond)),
				request(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{-1.0},
		},
		{
			Name: "request + response fully overlapping",
			PNTs: []akinet.ParsedNetworkTraffic{
				request(streamID, seq, startTime, startTime),
				response(streamID, seq, startTime, startTime),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{0.0},
		},
		{
			Name: "response + request fully overlapping",
			PNTs: []akinet.ParsedNetworkTraffic{
				response(streamID, seq, startTime, startTime),
				request(streamID, seq, startTime, startTime),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{0.0},
		},
		{
			Name: "request + response out of order",
			PNTs: []akinet.ParsedNetworkTraffic{
				request(streamID, seq, startTime.Add(3*time.Millisecond), startTime.Add(4*time.Millisecond)),
				response(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{-4.0},
		},
		{
			Name: "response + request out of order",
			PNTs: []akinet.ParsedNetworkTraffic{
				response(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
				request(streamID, seq, startTime.Add(3*time.Millisecond), startTime.Add(4*time.Millisecond)),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{-4.0},
		},
		{
			Name: "request + response zero timestamps",
			PNTs: []akinet.ParsedNetworkTraffic{
				request(streamID, seq, time.Time{}, time.Time{}),
				response(streamID, seq, time.Time{}, time.Time{}),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{0.0},
		},
		{
			Name: "response + request zero timestamps",
			PNTs: []akinet.ParsedNetworkTraffic{
				response(streamID, seq, time.Time{}, time.Time{}),
				request(streamID, seq, time.Time{}, time.Time{}),
			},
			ExpectedWitnesses: 1,
			ExpectedLatencies: []float32{0.0},
		},
		{
			Name: "interleaved request + response pairs",
			PNTs: []akinet.ParsedNetworkTraffic{
				request(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
				request(streamID, seq+1, startTime.Add(1*time.Millisecond), startTime.Add(3*time.Millisecond)),
				response(streamID, seq, startTime.Add(5*time.Millisecond), startTime.Add(7*time.Millisecond)),
				response(streamID, seq+1, startTime.Add(6*time.Millisecond), startTime.Add(8*time.Millisecond)),
			},
			ExpectedWitnesses: 2,
			ExpectedLatencies: []float32{3.0, 3.0},
		},
		{
			// Here we are testing the existance of a bug (the two requests get matched together and the two responses get matched together)
			// If it suddenly starts failing there is a very good chance that you fixed the bug!
			Name: "pipelined request + response pairs",
			PNTs: []akinet.ParsedNetworkTraffic{
				request(streamID, seq, startTime, startTime.Add(2*time.Millisecond)),
				request(streamID, seq, startTime.Add(1*time.Millisecond), startTime.Add(3*time.Millisecond)),
				response(streamID, seq, startTime.Add(5*time.Millisecond), startTime.Add(7*time.Millisecond)),
				response(streamID, seq, startTime.Add(6*time.Millisecond), startTime.Add(8*time.Millisecond)),
			},
			ExpectedWitnesses: 2,
			ExpectedLatencies: []float32{0.0, 0.0},
		},
	}

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockClient := mockrest.NewMockLearnClient(ctrl)
			defer ctrl.Finish()

			rec := newWitnessRecorder()
			mockClient.
				EXPECT().
				AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
				Do(rec.recordAsyncReportsUpload).
				AnyTimes().
				Return(nil)

			mockClient.
				EXPECT().
				GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
				AnyTimes().
				Return(kgxapi.NewServiceAgentConfig(), nil)

			redactor, err := data_masks.NewRedactor(fakeSvc, mockClient)
			assert.NoError(t, err)

			col := NewBackendCollector(
				fakeSvc,
				map[tags.Key]string{},
				fakeLrn,
				mockClient,
				redactor,
				optionals.None[int](),
				NewPacketCounter(),
				false,
				nil,
				apispec.DefaultMaxWintessUploadBuffers,
			)
			for _, pnt := range test.PNTs {
				assert.NoError(t, col.Process(pnt))
			}
			assert.NoError(t, col.Close())

			rec.assertExpectedWitnessLatency(t, test.ExpectedWitnesses, test.ExpectedLatencies)
		})
	}
}

// Demonstrate race condition with multiple interfaces
func TestMultipleInterfaces(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()
	mockClient.EXPECT().
		AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(nil)
	mockClient.
		EXPECT().
		GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(kgxapi.NewServiceAgentConfig(), nil)

	redactor, err := data_masks.NewRedactor(fakeSvc, mockClient)
	assert.NoError(t, err)

	bc := NewBackendCollector(
		fakeSvc,
		map[tags.Key]string{},
		fakeLrn,
		mockClient,
		redactor,
		optionals.None[int](),
		NewPacketCounter(),
		false,
		nil,
		apispec.DefaultMaxWintessUploadBuffers,
	)

	var wg sync.WaitGroup
	fakeTrace := func(count int, start_seq int) {
		for i := 0; i < count; i++ {
			streamID := uuid.New()
			// Re-using the example above
			req := akinet.ParsedNetworkTraffic{
				Content: akinet.HTTPRequest{
					StreamID: streamID,
					Seq:      start_seq + count,
					Method:   "POST",
					URL: &url.URL{
						Path: "/v1/doggos",
					},
					Host: "example.com",
					Header: map[string][]string{
						"Content-Type": {"application/json"},
					},
					Body: memview.New([]byte(`{"name": "prince", "number": 6119717375543385000}`)),
				},
			}
			bc.Process(req)
			resp := akinet.ParsedNetworkTraffic{
				Content: akinet.HTTPResponse{
					StreamID:   streamID,
					Seq:        start_seq + count,
					StatusCode: 200,
					Header: map[string][]string{
						"Content-Type": {"application/json"},
					},
					Body: memview.New([]byte(`{"homes": ["burbank, ca", "jeuno, ak", "versailles"]}`)),
				},
			}
			bc.Process(resp)
		}
		wg.Done()
	}

	wg.Add(2)
	go fakeTrace(100, 1000)
	go fakeTrace(200, 2000)

	wg.Wait()
}

// Demonstrate that periodic flush exits
func TestFlushExit(t *testing.T) {
	b := &BackendCollector{}
	b.uploadReportBatch = batcher.NewInMemory[rawReport](
		newReportBuffer(b, NewPacketCounter(), uploadBatchMaxSize_bytes, optionals.None[int](), false, apispec.DefaultMaxWintessUploadBuffers),
		uploadBatchFlushDuration,
	)
	b.flushDone = make(chan struct{})
	close(b.flushDone)
	b.periodicFlush()
	// Test should exit immediately
}

func TestOnlyRedactNonErrorResponses(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()

	rec := newWitnessRecorder()
	mockClient.
		EXPECT().
		AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(rec.recordAsyncReportsUpload).
		AnyTimes().
		Return(nil)

	mockClient.
		EXPECT().
		GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(kgxapi.NewServiceAgentConfig(), nil)

	streamID := uuid.New()
	req := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPRequest{
			StreamID: streamID,
			Seq:      1203,
			Method:   "POST",
			URL: &url.URL{
				Path: "/v1/doggos",
			},
			Host: "example.com",
			Header: map[string][]string{
				"Content-Type": {"application/json"},
			},
			Body: memview.New([]byte(`{"name": "prince", "number": 6119717375543385000}`)),
		},
	}

	resp := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPResponse{
			StreamID:   streamID,
			Seq:        1203,
			StatusCode: 200,
			Header: map[string][]string{
				"Content-Type": {"application/json"},
			},
			Body: memview.New([]byte(`{"homes": ["burbank, ca", "jeuno, ak", "versailles"]}`)),
		},
	}

	errStreamID := uuid.New()
	errReq := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPRequest{
			StreamID: errStreamID,
			Seq:      1204,
			Method:   "POST",
			URL: &url.URL{
				Path: "/v1/doggos",
			},
			Host: "example.com",
			Header: map[string][]string{
				"Content-Type": {"application/json"},
			},
			Body: memview.New([]byte(`{"name": "error", "number": 202410081550}`)),
		},
	}

	errResp := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPResponse{
			StreamID:   errStreamID,
			Seq:        1204,
			StatusCode: 404,
			Header: map[string][]string{
				"Content-Type": {"application/json"},
			},
			Body: memview.New([]byte(`{"homes": ["error", "happened", "here"]}`)),
		},
	}

	redactor, err := data_masks.NewRedactor(fakeSvc, mockClient)
	assert.NoError(t, err)

	col := NewBackendCollector(
		fakeSvc,
		map[tags.Key]string{},
		fakeLrn,
		mockClient,
		redactor,
		optionals.None[int](),
		NewPacketCounter(),
		true,
		nil,
		apispec.DefaultMaxWintessUploadBuffers,
	)
	assert.NoError(t, col.Process(req))
	assert.NoError(t, col.Process(resp))
	assert.NoError(t, col.Process(errReq))
	assert.NoError(t, col.Process(errResp))
	assert.NoError(t, col.Close())

	expectedWitnesses := []*pb.Witness{
		{
			Method: &pb.Method{
				Id: &pb.MethodID{
					ApiType: pb.ApiType_HTTP_REST,
				},
				Args: map[string]*pb.Data{
					"nxnOc5Qy3D4=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
						"name":   dataFromPrimitive(spec_util.NewPrimitiveString("")),
						"number": dataFromPrimitive(spec_util.NewPrimitiveInt64(0)),
					}),
				},
				Responses: map[string]*pb.Data{
					"AyBUQkT0SHU=": newTestBodySpecFromStruct(200, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
						"homes": dataFromList(
							dataFromPrimitive(spec_util.NewPrimitiveString("")),
							dataFromPrimitive(spec_util.NewPrimitiveString("")),
							dataFromPrimitive(spec_util.NewPrimitiveString("")),
						),
					}),
				},
				Meta: &pb.MethodMeta{
					Meta: &pb.MethodMeta_Http{
						Http: &pb.HTTPMethodMeta{
							Method:       "POST",
							PathTemplate: "/v1/doggos",
							Host:         "example.com",
							Obfuscation:  pb.HTTPMethodMeta_ZERO_VALUE,
						},
					},
				},
			},
		},
		{
			Method: &pb.Method{
				Id: &pb.MethodID{
					ApiType: pb.ApiType_HTTP_REST,
				},
				Args: map[string]*pb.Data{
					"MWeG2T99uHI=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
						"name":   dataFromPrimitive(spec_util.NewPrimitiveString("error")),
						"number": dataFromPrimitive(spec_util.NewPrimitiveInt64(202410081550)),
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
							Obfuscation:  pb.HTTPMethodMeta_NONE,
						},
					},
				},
			},
		},
	}

	rec.assertExpectedWitnesses(t, expectedWitnesses)
}

func TestRedactionConfigs(t *testing.T) {
	// Prepare a test cases
	streamID := uuid.New()
	type testCase struct {
		request           akinet.HTTPRequest
		response          akinet.HTTPResponse
		expectedWitnesses *pb.Witness
	}
	testCases := map[string]testCase{
		"no sensitive data": {
			request: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      1204,
				Method:   "POST",
				URL: &url.URL{
					Path: "/v1/doggos",
				},
				Host: "example.com",
				Header: map[string][]string{
					"Content-Type":  {"application/json"},
					"Normal-Header": {"Normal-Value"},
				},
				Body: memview.New([]byte(`{
					"name": "error",
					"number": 202410081550
				}`)),
			},
			response: akinet.HTTPResponse{
				StreamID:   streamID,
				Seq:        1204,
				StatusCode: 404,
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{
					"homes": ["error", "happened", "here"]
				}`)),
			},
			expectedWitnesses: &pb.Witness{
				Method: &pb.Method{
					Id: &pb.MethodID{
						ApiType: pb.ApiType_HTTP_REST,
					},
					Args: map[string]*pb.Data{
						"KC2RO-pCNJA=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString("Normal-Value")), "Normal-Header", 0),
						"MWeG2T99uHI=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
							"name":   dataFromPrimitive(spec_util.NewPrimitiveString("error")),
							"number": dataFromPrimitive(spec_util.NewPrimitiveInt64(202410081550)),
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
								Obfuscation:  pb.HTTPMethodMeta_NONE,
							},
						},
					},
				},
			},
		},
		"sensitive data in header, query param, cookie and URL path": {
			request: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      1204,
				Method:   "POST",
				URL: &url.URL{
					Path:     "/v1/doggos/PMAK-6717875c69335700017b1c46/api-key/PMAK-6717875c69335700017b1c46",
					RawQuery: "sso_jwt_key=XX__X_X_X_X&pmak_in_query=PMAK-6717875c69335700017b1c46",
				},
				Host: "example.com",
				Header: map[string][]string{
					"Content-Type":   {"application/json"},
					"Authorization":  {"XX__X_X_X_X"},
					"Normal-Header":  {"Normal-Value"},
					"x-access-token": {"XX__X_X_X_X"},
					"pmak_in_header": {"PMAK-6717875c69335700017b1c46"},
				},
				Body: memview.New([]byte(`{
					"name": "error",
					"number": 202410081550,
					"normal2DArray": [
						[1,2,3],
						["four","five","six"]
					]
				}`)),
			},
			response: akinet.HTTPResponse{
				StreamID:   streamID,
				Seq:        1204,
				StatusCode: 404,
				Header: map[string][]string{
					"Content-Type": {"application/json"},
					"postman_sid":  {"XX__X_X_X_X"},
				},
				Cookies: []*http.Cookie{
					{
						Name:  "Random-Cookie",
						Value: "Random-Cookie-Value",
					},
				},
				Body: memview.New([]byte(`{
					"homes": ["error", "happened", "here"]
				}`)),
			},
			expectedWitnesses: &pb.Witness{
				Method: &pb.Method{
					Id: &pb.MethodID{
						ApiType: pb.ApiType_HTTP_REST,
					},
					Args: map[string]*pb.Data{
						"4F1vWo8G_-Q=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)), "x-access-token", 0),
						"KC2RO-pCNJA=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString("Normal-Value")), "Normal-Header", 0),
						"xwb2G1yYVVc=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)), "pmak_in_header", 0),
						"9NijbeQiJAg=": newTestQueryParamSpec(dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)), "sso_jwt_key", 0),
						"b5t-IaNo7Ug=": newTestQueryParamSpec(dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)), "pmak_in_query", 0),
						"k5p4y9tXMAk=": newTestAuthSpec(dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)), 0),
						"K51zDh5OkH0=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
							"name":   dataFromPrimitive(spec_util.NewPrimitiveString("error")),
							"number": dataFromPrimitive(spec_util.NewPrimitiveInt64(202410081550)),
							"normal2DArray": dataFromList(
								dataFromList(
									dataFromPrimitive(spec_util.NewPrimitiveInt64(1)),
									dataFromPrimitive(spec_util.NewPrimitiveInt64(2)),
									dataFromPrimitive(spec_util.NewPrimitiveInt64(3)),
								),
								dataFromList(
									dataFromPrimitive(spec_util.NewPrimitiveString("four")),
									dataFromPrimitive(spec_util.NewPrimitiveString("five")),
									dataFromPrimitive(spec_util.NewPrimitiveString("six")),
								),
							),
						}),
					},
					Responses: map[string]*pb.Data{
						"hAjVb_ouhwQ=": newTestCookieSpec(dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)), "Random-Cookie", 404),
						"rZob7SB3qd0=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)), "postman_sid", 404),
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
								PathTemplate: "/v1/doggos/*REDACTED*/api-key/*REDACTED*",
								Host:         "example.com",
								Obfuscation:  pb.HTTPMethodMeta_NONE,
							},
						},
					},
				},
			},
		},
		"sensitive data in body": {
			request: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      1204,
				Method:   "POST",
				URL: &url.URL{
					Path: "/v1/doggos",
				},
				Host: "example.com",
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{
					"name": "error",
					"number": 202410081550,
					"pmakInBody": "PMAK-6717875c69335700017b1c46",
					"api_key": "XX__X_X_X_X"
				}`)),
			},
			response: akinet.HTTPResponse{
				StreamID:   streamID,
				Seq:        1204,
				StatusCode: 404,
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{
					"homes": ["error", "happened", "here"],
					"pmakInResponseBody": "PMAK-6717875c69335700017b1c46",
					"encryption_key": [1,2,3,4,5]
				}`)),
			},
			expectedWitnesses: &pb.Witness{
				Method: &pb.Method{
					Id: &pb.MethodID{
						ApiType: pb.ApiType_HTTP_REST,
					},
					Args: map[string]*pb.Data{
						"Ee95MCpMH0c=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
							"name":       dataFromPrimitive(spec_util.NewPrimitiveString("error")),
							"number":     dataFromPrimitive(spec_util.NewPrimitiveInt64(202410081550)),
							"pmakInBody": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
							"api_key":    dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
						}),
					},
					Responses: map[string]*pb.Data{
						"78vwENc96h0=": newTestBodySpecFromStruct(404, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
							"homes": dataFromList(
								dataFromPrimitive(spec_util.NewPrimitiveString("error")),
								dataFromPrimitive(spec_util.NewPrimitiveString("happened")),
								dataFromPrimitive(spec_util.NewPrimitiveString("here")),
							),
							"pmakInResponseBody": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
							"encryption_key": dataFromList(
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
							),
						}),
					},
					Meta: &pb.MethodMeta{
						Meta: &pb.MethodMeta_Http{
							Http: &pb.HTTPMethodMeta{
								Method:       "POST",
								PathTemplate: "/v1/doggos",
								Host:         "example.com",
								Obfuscation:  pb.HTTPMethodMeta_NONE,
							},
						},
					},
				},
			},
		},
		"struct with sensitive keys and values": {
			request: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      1204,
				Method:   "POST",
				URL: &url.URL{
					Path: "/v1/doggos",
				},
				Host: "example.com",
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{"name": "error"}`)),
			},
			response: akinet.HTTPResponse{
				StreamID:   streamID,
				Seq:        1204,
				StatusCode: 404,
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{
					"homes": ["error", "happened", "here"],
					"structList": [
						{
							"encryption_key": "XX__X_X_X_1",
							"index": 0
						},
						{
							"random_key": "PMAK-6717875c69335700017b1c46",
							"index": 1
						}
					],
					"sso_jwt_key": {
						"key1": "XX__X_X_X_1",
						"key2": [
							{
								"key2_1": "randomvalue"
							},
							{
								"key2_2": "PMAK-6717875c69335700017b1c46"
							}
						],
						"key3": [ 1, "PMAK-6717875c69335700017b1c46", 3]
					}
				}`)),
			},
			expectedWitnesses: &pb.Witness{
				Method: &pb.Method{
					Id: &pb.MethodID{
						ApiType: pb.ApiType_HTTP_REST,
					},
					Args: map[string]*pb.Data{
						"XP9rRmHnH0A=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
							"name": dataFromPrimitive(spec_util.NewPrimitiveString("error")),
						}),
					},
					Responses: map[string]*pb.Data{
						"zvyT9PDTBoM=": newTestBodySpecFromStruct(404, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
							"homes": dataFromList(
								dataFromPrimitive(spec_util.NewPrimitiveString("error")),
								dataFromPrimitive(spec_util.NewPrimitiveString("happened")),
								dataFromPrimitive(spec_util.NewPrimitiveString("here")),
							),
							"structList": dataFromList(
								dataFromStruct(map[string]*pb.Data{
									"encryption_key": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									"index":          dataFromPrimitive(spec_util.NewPrimitiveInt64(0)),
								}),
								dataFromStruct(map[string]*pb.Data{
									"random_key": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									"index":      dataFromPrimitive(spec_util.NewPrimitiveInt64(1)),
								}),
							),
							"sso_jwt_key": dataFromStruct(map[string]*pb.Data{
								"key1": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								"key2": dataFromList(
									dataFromStruct(map[string]*pb.Data{
										"key2_1": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									}),
									dataFromStruct(map[string]*pb.Data{
										"key2_2": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									}),
								),
								"key3": dataFromList(
									dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								),
							}),
						}),
					},
					Meta: &pb.MethodMeta{
						Meta: &pb.MethodMeta_Http{
							Http: &pb.HTTPMethodMeta{
								Method:       "POST",
								PathTemplate: "/v1/doggos",
								Host:         "example.com",
								Obfuscation:  pb.HTTPMethodMeta_NONE,
							},
						},
					},
				},
			},
		},
		"list with sensitive keys and values": {
			request: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      1204,
				Method:   "POST",
				URL: &url.URL{
					Path: "/v1/doggos",
				},
				Host: "example.com",
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{
					"name": "error",
					"encryption_key": [
						12323454,
						"onetwothreetwothreesoon",
						{
							"index": 3,
							"value": "III"
						}
					],
					"sso_jwt_key": [
						[1,2],
						["one","two"],
						[
							{"index": 0, "value": "I"},
							{"index": 1, "value": "II"}
						]
					]
				}`)),
			},
			response: akinet.HTTPResponse{
				StreamID:   streamID,
				Seq:        1204,
				StatusCode: 404,
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{
					"homes": ["error", "happened", "here"],
					"encryption_key": ["one","PMAK-6717875c69335700017b1c46"],
					"normal_list": [1,"two","PMAK-6717875c69335700017b1c46","IV",5]
				}`)),
			},
			expectedWitnesses: &pb.Witness{
				Method: &pb.Method{
					Id: &pb.MethodID{
						ApiType: pb.ApiType_HTTP_REST,
					},
					Args: map[string]*pb.Data{
						"gZwJ7G0xsTU=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
							"name": dataFromPrimitive(spec_util.NewPrimitiveString("error")),
							"encryption_key": dataFromList(
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								dataFromStruct(map[string]*pb.Data{
									"index": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									"value": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								}),
							),
							"sso_jwt_key": dataFromList(
								dataFromList(
									dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								),
								dataFromList(
									dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								),
								dataFromList(
									dataFromStruct(map[string]*pb.Data{
										"index": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
										"value": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									}),
									dataFromStruct(map[string]*pb.Data{
										"index": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
										"value": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
									}),
								),
							),
						}),
					},
					Responses: map[string]*pb.Data{
						"0BdogXDRY7U=": newTestBodySpecFromStruct(404, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
							"homes": dataFromList(
								dataFromPrimitive(spec_util.NewPrimitiveString("error")),
								dataFromPrimitive(spec_util.NewPrimitiveString("happened")),
								dataFromPrimitive(spec_util.NewPrimitiveString("here")),
							),
							"encryption_key": dataFromList(
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
							),
							"normal_list": dataFromList(
								dataFromPrimitive(spec_util.NewPrimitiveInt64(1)),
								dataFromPrimitive(spec_util.NewPrimitiveString("two")),
								dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								dataFromPrimitive(spec_util.NewPrimitiveString("IV")),
								dataFromPrimitive(spec_util.NewPrimitiveInt64(5)),
							),
						}),
					},
					Meta: &pb.MethodMeta{
						Meta: &pb.MethodMeta_Http{
							Http: &pb.HTTPMethodMeta{
								Method:       "POST",
								PathTemplate: "/v1/doggos",
								Host:         "example.com",
								Obfuscation:  pb.HTTPMethodMeta_NONE,
							},
						},
					},
				},
			},
		},
		"multipart data, no sensitive data": {
			request: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      1204,
				Method:   "POST",
				URL: &url.URL{
					Path: "/v1/doggos",
				},
				Host: "example.com",
				Header: map[string][]string{
					"Content-Type": {"multipart/form-data;boundary=XXXX"},
				},
				Body: memview.New([]byte(
					strings.Join([]string{
						"--XXXX\r\n",
						"Content-Disposition: form-data; name=\"field1\"\r\n",
						"\r\n",
						"value1\r\n",
						"--XXXX\r\n",
						"Content-Disposition: form-data; name=\"field2\"\r\n",
						"Content-Type: application/json\r\n",
						"\r\n",
						`{"foo": "bar", "baz": 123}` + "\r\n",
						"--XXXX--",
					}, ""),
				)),
			},
			response: akinet.HTTPResponse{
				StreamID:   streamID,
				Seq:        1204,
				StatusCode: 404,
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{
					"homes": ["error", "happened", "here"]
				}`)),
			},
			expectedWitnesses: &pb.Witness{
				Method: &pb.Method{
					Id: &pb.MethodID{
						ApiType: pb.ApiType_HTTP_REST,
					},
					Args: map[string]*pb.Data{
						"LsTelHFYzIY=": newTestMultipartFormDataSpec(0, dataFromStruct(map[string]*pb.Data{
							"field1": newTestBodySpecFromData(0, pb.HTTPBody_TEXT_PLAIN, "text/plain", dataFromPrimitive(spec_util.NewPrimitiveString("value1"))),
							"field2": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
								"foo": dataFromPrimitive(spec_util.NewPrimitiveString("bar")),
								"baz": dataFromPrimitive(spec_util.NewPrimitiveInt64(123)),
							}),
						}),
						),
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
								Obfuscation:  pb.HTTPMethodMeta_NONE,
							},
						},
					},
				},
			},
		},
		"multipart data, with sensitive data": {
			request: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      1204,
				Method:   "POST",
				URL: &url.URL{
					Path: "/v1/doggos",
				},
				Host: "example.com",
				Header: map[string][]string{
					"Content-Type": {"multipart/form-data;boundary=XXXX"},
				},
				Body: memview.New([]byte(
					strings.Join([]string{
						"--XXXX\r\n",
						"Content-Disposition: form-data; name=\"sensitiveValue\"\r\n",
						"\r\n",
						"PMAK-6717875c69335700017b1c46\r\n",
						"--XXXX\r\n",
						"Content-Disposition: form-data; name=\"encryption_key\"\r\n",
						"\r\n",
						"sensitiveKey\r\n",
						"--XXXX\r\n",
						"Content-Disposition: form-data; name=\"jsonData\"\r\n",
						"Content-Type: application/json\r\n",
						"\r\n",
						`{"x-access-token": "sensitiveKey", "senstiveValue": "PMAK-6717875c69335700017b1c46"}` + "\r\n",
						"--XXXX\r\n",
						"Content-Disposition: form-data; name=\"api_key\"\r\n",
						"Content-Type: application/json\r\n",
						"\r\n",
						`{"resursive_struct": "sensitiveKey", "number": 12345}` + "\r\n",
						"--XXXX--",
					}, ""),
				)),
			},
			response: akinet.HTTPResponse{
				StreamID:   streamID,
				Seq:        1204,
				StatusCode: 404,
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{
					"homes": ["error", "happened", "here"]
				}`)),
			},
			expectedWitnesses: &pb.Witness{
				Method: &pb.Method{
					Id: &pb.MethodID{
						ApiType: pb.ApiType_HTTP_REST,
					},
					Args: map[string]*pb.Data{
						"MRlGYcEp0Bc=": newTestMultipartFormDataSpec(0, dataFromStruct(map[string]*pb.Data{
							"sensitiveValue": newTestBodySpecFromData(0, pb.HTTPBody_TEXT_PLAIN, "text/plain", dataFromPrimitive(spec_util.NewPrimitiveString(redactionString))),
							"encryption_key": newTestBodySpecFromData(0, pb.HTTPBody_TEXT_PLAIN, "text/plain", dataFromPrimitive(spec_util.NewPrimitiveString(redactionString))),
							"jsonData": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
								"x-access-token": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								"senstiveValue":  dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
							}),
							"api_key": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
								"resursive_struct": dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
								"number":           dataFromPrimitive(spec_util.NewPrimitiveString(redactionString)),
							}),
						}),
						),
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
								Obfuscation:  pb.HTTPMethodMeta_NONE,
							},
						},
					},
				},
			},
		},
		"null value": {
			request: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      1204,
				Method:   "POST",
				URL: &url.URL{
					Path: "/",
				},
				Host: "example.com",
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`
					{
						"null": null
					}
				`)),
			},
			response: akinet.HTTPResponse{
				StreamID:   streamID,
				Seq:        1204,
				StatusCode: 404,
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`
				  {
						"null": null
				  }
				`)),
			},
			expectedWitnesses: &pb.Witness{
				Method: &pb.Method{
					Id: &pb.MethodID{
						ApiType: pb.ApiType_HTTP_REST,
					},
					Args: map[string]*pb.Data{
						"sLSDNjJ5umQ=": newTestBodySpecFromStruct(
							0,
							pb.HTTPBody_JSON,
							"application/json",
							map[string]*pb.Data{
								"null": spec_util.NoneData,
							},
						),
					},
					Responses: map[string]*pb.Data{
						"2drZdoQw74E=": newTestBodySpecFromStruct(
							404,
							pb.HTTPBody_JSON,
							"application/json",
							map[string]*pb.Data{
								"null": spec_util.NoneData,
							},
						),
					},
					Meta: &pb.MethodMeta{
						Meta: &pb.MethodMeta_Http{
							Http: &pb.HTTPMethodMeta{
								Method:       "POST",
								PathTemplate: "/",
								Host:         "example.com",
								Obfuscation:  pb.HTTPMethodMeta_NONE,
							},
						},
					},
				},
			},
		},
	}

	// Setup for running tests
	ctrl := gomock.NewController(t)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()

	rec := newWitnessRecorder()
	mockClient.
		EXPECT().
		AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(rec.recordAsyncReportsUpload).
		AnyTimes().
		Return(nil)

	mockClient.
		EXPECT().
		GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(kgxapi.NewServiceAgentConfig(), nil)

	i := -1
	for name, testCase := range testCases {
		i++
		fmt.Println("Running test case: ", name)

		req := akinet.ParsedNetworkTraffic{Content: testCase.request}
		resp := akinet.ParsedNetworkTraffic{Content: testCase.response}

		redactor, err := data_masks.NewRedactor(fakeSvc, mockClient)
		assert.NoError(t, err)

		col := NewBackendCollector(
			fakeSvc,
			map[tags.Key]string{},
			fakeLrn,
			mockClient,
			redactor,
			optionals.None[int](),
			NewPacketCounter(),
			true,
			nil,
			apispec.DefaultMaxWintessUploadBuffers,
		)
		assert.NoError(t, col.Process(req))
		assert.NoError(t, col.Process(resp))
		assert.NoError(t, col.Close())

		rec.assertExpectedWitnesses(t, []*pb.Witness{testCase.expectedWitnesses})
	}
}
