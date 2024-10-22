package trace

import (
	"regexp"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/spec_util"
	. "github.com/akitasoftware/akita-libs/visitors"
	vis "github.com/akitasoftware/akita-libs/visitors/http_rest"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

type Obfuscator struct {
	SensitiveDataKeys          []string
	SensitiveDataValuePatterns []*regexp.Regexp
}

func NewObfuscator() *Obfuscator {
	config, err := configFromFile("obfuscation_config.yaml")
	if err != nil {
		printer.Errorf("failed to load obfuscation config: %v\n", err)
		return nil
	}

	sensitiveDataRegex := make([]*regexp.Regexp, len(config.SensitiveValueRegexes))

	// Compile regex patterns.
	for i, pattern := range config.SensitiveValueRegexes {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			printer.Errorf("failed to compile regex pattern %s: %v\n", pattern, err)
			return nil
		}
		sensitiveDataRegex[i] = regex
	}

	return &Obfuscator{
		SensitiveDataKeys:          config.SensitiveKeys,
		SensitiveDataValuePatterns: sensitiveDataRegex,
	}
}

func (o *Obfuscator) obfuscate(m *pb.Method, obfuscateWholePayload bool) {
	if obfuscateWholePayload {
		var ov obfuscationVisitor
		vis.Apply(&ov, m)

		// Mark the method as obfuscated.
		m.GetMeta().GetHttp().Obfuscation = pb.HTTPMethodMeta_ZERO_VALUE
		return
	}

	pov := partialObfuscationVisitor{
		obfuscationOptions: o,
	}
	vis.Apply(&pov, m)
	return
}

type obfuscationVisitor struct {
	vis.DefaultSpecVisitorImpl
}

var _ vis.DefaultSpecVisitor = (*obfuscationVisitor)(nil)

func (*obfuscationVisitor) EnterData(self interface{}, ctx vis.SpecVisitorContext, d *pb.Data) Cont {
	return ObfuscateWithZeroValue(d)
}

type partialObfuscationVisitor struct {
	vis.DefaultSpecVisitorImpl
	obfuscationOptions *Obfuscator
}

var _ vis.DefaultSpecVisitor = (*partialObfuscationVisitor)(nil)

func (pov *partialObfuscationVisitor) EnterData(self interface{}, ctx vis.SpecVisitorContext, d *pb.Data) Cont {
	authorization := spec_util.HTTPAuthFromData(d)
	if authorization != nil {
		return ObfuscateWithZeroValue(d)
	}

	var key string

	header := spec_util.HTTPHeaderFromData(d)
	if header != nil {
		key = header.Key
	}
	queryParam := spec_util.HTTPQueryFromData(d)
	if queryParam != nil {
		key = queryParam.Key
	}
	pathParam := spec_util.HTTPPathFromData(d)
	if pathParam != nil {
		key = pathParam.Key
	}

	// Check if the key is in the list of keys to obfuscate.
	for _, k := range pov.obfuscationOptions.SensitiveDataKeys {
		if k == key {
			return ObfuscateWithZeroValue(d)
		}
	}

	dp, isPrimitive := d.GetValue().(*pb.Data_Primitive)
	if !isPrimitive {
		return Continue
	}

	stringValue := dp.Primitive.GetStringValue()
	if stringValue == nil {
		// Not a string, regex will be applied to string values only.
		return Continue
	}

	for _, pattern := range pov.obfuscationOptions.SensitiveDataValuePatterns {
		if pattern.MatchString(stringValue.Value) {
			return ObfuscateWithZeroValue(d)
		}
	}

	return Continue
}

func ObfuscateWithZeroValue(d *pb.Data) Cont {
	dp, isPrimitive := d.GetValue().(*pb.Data_Primitive)
	if !isPrimitive {
		return Continue
	}

	pv, err := spec_util.PrimitiveValueFromProto(dp.Primitive)
	if err != nil {
		printer.Warningf("failed to obfuscate raw value, dropping\n")
		d.Value = nil
		return Continue
	}

	dp.Primitive.Value = pv.Obfuscate().ToProto().Value
	return Continue
}
