package test_utils

import (
	pb "github.com/akitasoftware/akita-ir/go/api_spec"
)

func DataFromPrimitive(p *pb.Primitive) *pb.Data {
	return &pb.Data{Value: &pb.Data_Primitive{Primitive: p}}
}

func DataFromStruct(fields map[string]*pb.Data) *pb.Data {
	return &pb.Data{Value: &pb.Data_Struct{Struct: &pb.Struct{Fields: fields}}}
}

func DataFromList(elems ...*pb.Data) *pb.Data {
	return &pb.Data{Value: &pb.Data_List{List: &pb.List{Elems: elems}}}
}

func NewTestBodySpecFromStruct(statusCode int, contentType pb.HTTPBody_ContentType, originalContentType string, s map[string]*pb.Data) *pb.Data {
	return NewTestBodySpecFromData(statusCode, contentType, originalContentType, DataFromStruct(s))
}

func NewTestBodySpecFromData(statusCode int, contentType pb.HTTPBody_ContentType, originalContentType string, d *pb.Data) *pb.Data {
	d.Meta = NewBodyDataMeta(statusCode, contentType, originalContentType)
	return d
}

func NewTestMultipartFormDataSpec(responseCode int, d *pb.Data) *pb.Data {
	d.Meta = NewDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Multipart{
			Multipart: &pb.HTTPMultipart{
				Type: "form-data",
			},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}

func NewBodyDataMeta(responseCode int, contentType pb.HTTPBody_ContentType, originalContentType string) *pb.DataMeta {
	return NewDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Body{
			Body: &pb.HTTPBody{
				ContentType: contentType,
				OtherType:   originalContentType,
			},
		},
		ResponseCode: int32(responseCode),
	})
}

func NewDataMeta(httpM *pb.HTTPMeta) *pb.DataMeta {
	return &pb.DataMeta{
		Meta: &pb.DataMeta_Http{
			Http: httpM,
		},
	}
}

func NewTestHeaderSpec(d *pb.Data, key string, responseCode int) *pb.Data {
	d.Meta = NewDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Header{
			Header: &pb.HTTPHeader{
				Key: key,
			},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}

func NewTestQueryParamSpec(d *pb.Data, key string, responseCode int) *pb.Data {
	d.Meta = NewDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Query{
			Query: &pb.HTTPQuery{
				Key: key,
			},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}

func NewTestAuthSpec(d *pb.Data, responseCode int) *pb.Data {
	d.Meta = NewDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Auth{
			Auth: &pb.HTTPAuth{},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}

func NewTestCookieSpec(d *pb.Data, key string, responseCode int) *pb.Data {
	d.Meta = NewDataMeta(&pb.HTTPMeta{
		Location: &pb.HTTPMeta_Cookie{
			Cookie: &pb.HTTPCookie{
				Key: key,
			},
		},
		ResponseCode: int32(responseCode),
	})
	return d
}
