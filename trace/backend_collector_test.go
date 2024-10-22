package trace

import (
	"encoding/base64"
	"net/http"
	"net/url"
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
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	mockrest "github.com/postmanlabs/postman-insights-agent/rest/mock"
	"github.com/stretchr/testify/assert"
)

var (
	fakeSvc = akid.NewServiceID(uuid.Must(uuid.Parse("8b2cf196-87fe-4e53-a6b9-1452d7efb863")))
	fakeLrn = akid.NewLearnSessionID(uuid.Must(uuid.Parse("2b5dd735-9fc0-4365-93e8-74bf86d3f853")))
)

type witnessRecorder struct {
	witnesses []*pb.Witness
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
		wr.witnesses = append(wr.witnesses, w)
	}
}

// Make sure we obfuscate values before uploading.
func TestObfuscate(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()

	var rec witnessRecorder
	mockClient.
		EXPECT().
		AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(rec.recordAsyncReportsUpload).
		AnyTimes().
		Return(nil)

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

	col := NewBackendCollector(fakeSvc, fakeLrn, mockClient, optionals.None[int](), NewPacketCounter(), false, nil)
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

	for i := range expectedWitnesses {
		expected := proto.MarshalTextString(expectedWitnesses[i])
		actual := proto.MarshalTextString(rec.witnesses[i])
		assert.Equal(t, expected, actual)
	}
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
	ctrl := gomock.NewController(t)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()

	var rec witnessRecorder
	mockClient.
		EXPECT().
		AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(rec.recordAsyncReportsUpload).
		AnyTimes().
		Return(nil)

	streamID := uuid.New()
	startTime := time.Now()

	req := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPRequest{
			StreamID: streamID,
			Seq:      1203,
			Method:   "GET",
			URL: &url.URL{
				Path: "/v1/doggos",
			},
			Host: "example.com",
		},
		ObservationTime: startTime,
		FinalPacketTime: startTime.Add(2 * time.Millisecond),
	}

	resp := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPResponse{
			StreamID:   streamID,
			Seq:        1203,
			StatusCode: 200,
		},
		ObservationTime: startTime.Add(10 * time.Millisecond),
		FinalPacketTime: startTime.Add(13 * time.Millisecond),
	}

	col := NewBackendCollector(fakeSvc, fakeLrn, mockClient, optionals.None[int](), NewPacketCounter(), false, nil)
	assert.NoError(t, col.Process(req))
	assert.NoError(t, col.Process(resp))
	assert.NoError(t, col.Close())

	assert.Equal(t, 1, len(rec.witnesses))
	actual := rec.witnesses[0]
	meta := spec_util.HTTPMetaFromMethod(actual.Method)
	assert.NotNil(t, meta)
	assert.InDelta(t, 8.0, meta.ProcessingLatency, 0.001)
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

	bc := NewBackendCollector(fakeSvc, fakeLrn, mockClient, optionals.None[int](), NewPacketCounter(), false, nil)

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
		newReportBuffer(b, NewPacketCounter(), uploadBatchMaxSize_bytes, optionals.None[int](), false),
		uploadBatchFlushDuration,
	)
	b.flushDone = make(chan struct{})
	close(b.flushDone)
	b.periodicFlush()
	// Test should exit immediately
}

func TestOnlyObfuscateNonErrorResponses(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()

	var rec witnessRecorder
	mockClient.
		EXPECT().
		AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(rec.recordAsyncReportsUpload).
		AnyTimes().
		Return(nil)

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

	col := NewBackendCollector(fakeSvc, fakeLrn, mockClient, optionals.None[int](), NewPacketCounter(), true, nil)
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

	for i := range expectedWitnesses {
		expected := proto.MarshalTextString(expectedWitnesses[i])
		actual := proto.MarshalTextString(rec.witnesses[i])
		assert.Equal(t, expected, actual)
	}
}

func TestObfuscationConfigs(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	defer ctrl.Finish()

	var rec witnessRecorder
	mockClient.
		EXPECT().
		AsyncReportsUpload(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(rec.recordAsyncReportsUpload).
		AnyTimes().
		Return(nil)

	errStreamID := uuid.New()
	errReq := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPRequest{
			StreamID: errStreamID,
			Seq:      1204,
			Method:   "POST",
			URL: &url.URL{
				Path:     "/v1/doggos",
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
			Body: memview.New([]byte(`{"name": "error", "number": 202410081550, "pmakInBody": "PMAK-6717875c69335700017b1c46"}`)),
		},
	}

	errResp := akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPResponse{
			StreamID:   errStreamID,
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
			Body: memview.New([]byte(`{"homes": ["error", "happened", "here"], "pmakInResponseBody": "PMAK-6717875c69335700017b1c46"}`)),
		},
	}

	col := NewBackendCollector(fakeSvc, fakeLrn, mockClient, optionals.None[int](), NewPacketCounter(), true, nil)
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
					"4F1vWo8G_-Q=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString("")), "x-access-token", 0),
					"KC2RO-pCNJA=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString("Normal-Value")), "Normal-Header", 0),
					"xwb2G1yYVVc=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString("")), "pmak_in_header", 0),
					"9NijbeQiJAg=": newTestQueryParamSpec(dataFromPrimitive(spec_util.NewPrimitiveString("")), "sso_jwt_key", 0),
					"b5t-IaNo7Ug=": newTestQueryParamSpec(dataFromPrimitive(spec_util.NewPrimitiveString("")), "pmak_in_query", 0),
					"k5p4y9tXMAk=": newTestAuthSpec(dataFromPrimitive(spec_util.NewPrimitiveString("")), 0),
					"bxitt4RTL5k=": newTestBodySpecFromStruct(0, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
						"name":       dataFromPrimitive(spec_util.NewPrimitiveString("error")),
						"number":     dataFromPrimitive(spec_util.NewPrimitiveInt64(202410081550)),
						"pmakInBody": dataFromPrimitive(spec_util.NewPrimitiveString("")),
					}),
				},
				Responses: map[string]*pb.Data{
					"hAjVb_ouhwQ=": newTestCookieSpec(dataFromPrimitive(spec_util.NewPrimitiveString("")), "Random-Cookie", 404),
					"rZob7SB3qd0=": newTestHeaderSpec(dataFromPrimitive(spec_util.NewPrimitiveString("")), "postman_sid", 404),
					"cBn6EHKhiAA=": newTestBodySpecFromStruct(404, pb.HTTPBody_JSON, "application/json", map[string]*pb.Data{
						"homes": dataFromList(
							dataFromPrimitive(spec_util.NewPrimitiveString("error")),
							dataFromPrimitive(spec_util.NewPrimitiveString("happened")),
							dataFromPrimitive(spec_util.NewPrimitiveString("here")),
						),
						"pmakInResponseBody": dataFromPrimitive(spec_util.NewPrimitiveString("")),
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

	for i := range expectedWitnesses {
		expected := proto.MarshalTextString(expectedWitnesses[i])
		actual := proto.MarshalTextString(rec.witnesses[i])
		assert.Equal(t, expected, actual)
	}
}
