package data_masks

import (
	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/spec_util"
	. "github.com/akitasoftware/akita-libs/visitors"
	vis "github.com/akitasoftware/akita-libs/visitors/http_rest"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// Replaces all primitive values in the given method with zero values.
func ObfuscateMethod(m *pb.Method) {
	var ov zeroPrimitivesVisitor
	vis.Apply(&ov, m)

	// Mark the method as obfuscated.
	m.GetMeta().GetHttp().Obfuscation = pb.HTTPMethodMeta_ZERO_VALUE
}

// Replaces all primitive values with zero values.
type zeroPrimitivesVisitor struct {
	vis.DefaultSpecVisitorImpl
}

var _ vis.DefaultSpecVisitor = (*zeroPrimitivesVisitor)(nil)

// EnterData processes the given data and replaces all the primitive values
// with zero values, regardless of its metadata.
func (*zeroPrimitivesVisitor) EnterData(self interface{}, _ vis.SpecVisitorContext, d *pb.Data) Cont {
	dp := d.GetPrimitive()
	if dp == nil {
		return Continue
	}

	pv, err := spec_util.PrimitiveValueFromProto(dp)
	if err != nil {
		printer.Warningf("failed to zero out raw value, dropping\n")
		d.Value = nil
		return Continue
	}

	dp.Value = pv.Obfuscate().ToProto().Value
	return Continue
}
