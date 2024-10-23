package trace

import (
	"regexp"
	"strings"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/spec_util"
	. "github.com/akitasoftware/akita-libs/visitors"
	vis "github.com/akitasoftware/akita-libs/visitors/http_rest"
	"github.com/akitasoftware/go-utils/sets"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

type Obfuscator struct {
	SensitiveDataKeys          sets.Set[string]
	SensitiveDataValuePatterns sets.Set[*regexp.Regexp]
}

func NewObfuscator() *Obfuscator {
	// Load obfuscation config using relative path to load the config file.
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
		SensitiveDataKeys:          sets.NewSet(config.SensitiveKeys...),
		SensitiveDataValuePatterns: sets.NewSet(sensitiveDataRegex...),
	}
}

func (o *Obfuscator) Obfuscate(m *pb.Method, obfuscateWholePayload bool) {
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

// EnterData processes the given data and obfuscates all the primitive values with zero values, regardless of it's meta data.
func (*obfuscationVisitor) EnterData(self interface{}, ctx vis.SpecVisitorContext, d *pb.Data) Cont {
	dp := d.GetPrimitive()
	if dp == nil {
		return Continue
	}

	pv, err := spec_util.PrimitiveValueFromProto(dp)
	if err != nil {
		printer.Warningf("failed to obfuscate raw value, dropping\n")
		d.Value = nil
		return Continue
	}

	dp.Value = pv.Obfuscate().ToProto().Value
	return Continue
}

type partialObfuscationVisitor struct {
	vis.DefaultSpecVisitorImpl
	obfuscationOptions *Obfuscator
}

var _ vis.DefaultSpecVisitor = (*partialObfuscationVisitor)(nil)

// EnterData processes the given data and obfuscates sensitive information based on the provided obfuscation options.
// It does 3 checks to determine if the data contains sensitive information:
// 1. It checks if spec is an HTTP Authroization or Cookie data and obfuscates the value.
// 2. It cheks if spec is an HTTP Header or Query Param data and obfuscates the value if the key is in the list of sensitive keys.
// 3. It applies regex patterns to all obfuscate sensitive primitive string values.
func (pov *partialObfuscationVisitor) EnterData(self interface{}, ctx vis.SpecVisitorContext, d *pb.Data) Cont {
	if httpMeta := d.GetMeta().GetHttp(); httpMeta != nil {
		var key string
		switch httpMeta.Location.(type) {
		case *pb.HTTPMeta_Auth:
			return ObfuscateWithRedactedString(d)
		case *pb.HTTPMeta_Cookie:
			return ObfuscateWithRedactedString(d)
		case *pb.HTTPMeta_Header:
			header := httpMeta.GetHeader()
			key = header.Key
		case *pb.HTTPMeta_Query:
			queryParam := httpMeta.GetQuery()
			key = queryParam.Key
		}
		// Check if the key is in the list of keys to obfuscate.
		if pov.obfuscationOptions.SensitiveDataKeys.Contains(strings.ToLower(key)) {
			return ObfuscateWithRedactedString(d)
		}
	}

	primitive := d.GetPrimitive()
	if primitive == nil {
		// Not a primitive, regex will be applied to primitive string values only.
		return Continue
	}

	stringValue := primitive.GetStringValue()
	if stringValue == nil {
		// Not a string, regex will be applied to string values only.
		return Continue
	}

	for pattern, _ := range pov.obfuscationOptions.SensitiveDataValuePatterns {
		if pattern.MatchString(stringValue.Value) {
			return ObfuscateWithRedactedString(d)
		}
	}

	return Continue
}

func ObfuscateWithRedactedString(d *pb.Data) Cont {
	dp := d.GetPrimitive()
	if dp == nil {
		return Continue
	}

	dp.Value = spec_util.NewPrimitiveString("REDACTED").Value
	return Continue
}
