package trace

import (
	"reflect"
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

func (o *Obfuscator) ObfuscateData(m *pb.Method) {
	var ov obfuscationVisitor
	vis.Apply(&ov, m)

	// Mark the method as obfuscated.
	m.GetMeta().GetHttp().Obfuscation = pb.HTTPMethodMeta_ZERO_VALUE
	return
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

func (o *Obfuscator) RedactData(m *pb.Method) {
	pov := redactSensitiveInfoVisitor{
		obfuscationOptions: o,
	}
	vis.Apply(&pov, m)
}

type obfuscationVisitor struct {
	vis.DefaultSpecVisitorImpl
}

type redactSensitiveInfoVisitor struct {
	vis.DefaultSpecVisitorImpl
	obfuscationOptions *Obfuscator
}

var _ vis.DefaultSpecVisitor = (*redactSensitiveInfoVisitor)(nil)

// EnterData processes the given data and obfuscates sensitive information based on the provided obfuscation options.
// It does 3 checks to determine if the data contains sensitive information:
// 1. It checks if spec is an HTTP Authroization or Cookie data and obfuscates the value.
// 2. It cheks if spec is an HTTP Header or Query Param data and obfuscates the value if the key is in the list of sensitive keys.
// 3. It applies regex patterns to all obfuscate sensitive primitive string values.
func (s *redactSensitiveInfoVisitor) EnterData(self interface{}, ctx vis.SpecVisitorContext, d *pb.Data) Cont {
	if httpMeta := d.GetMeta().GetHttp(); httpMeta != nil {
		var key string
		switch httpMeta.Location.(type) {
		case *pb.HTTPMeta_Auth:
			return ObfuscatePrimitiveWithRedactedString(d)
		case *pb.HTTPMeta_Cookie:
			return ObfuscatePrimitiveWithRedactedString(d)
		case *pb.HTTPMeta_Header:
			header := httpMeta.GetHeader()
			key = header.Key
		case *pb.HTTPMeta_Query:
			queryParam := httpMeta.GetQuery()
			key = queryParam.Key
		}
		// Check if the key is in the list of keys to obfuscate.
		if s.obfuscationOptions.SensitiveDataKeys.Contains(strings.ToLower(key)) {
			return ObfuscatePrimitiveWithRedactedString(d)
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

	for pattern, _ := range s.obfuscationOptions.SensitiveDataValuePatterns {
		if pattern.MatchString(stringValue.Value) {
			return ObfuscatePrimitiveWithRedactedString(d)
		}
	}

	return Continue
}

func (s *redactSensitiveInfoVisitor) EnterHTTPBody(self interface{}, ctx vis.SpecVisitorContext, b *pb.HTTPBody) Cont {
	node, _ := ctx.GetInnermostNode(reflect.TypeOf((*pb.Data)(nil)))
	data := node.(*pb.Data)
	if data == nil {
		return Continue
	}

	// Traverse the data node and redact sensitive information.
	s.traverseAndRedactSensitiveInfo(ctx, data)

	return Continue
}

func (s *redactSensitiveInfoVisitor) traverseAndRedactSensitiveInfo(ctx vis.SpecVisitorContext, data *pb.Data) {
	switch val := data.Value.(type) {
	case *pb.Data_Struct:
		// Traverse the struct's fields and redact sensitive information based on key.
		structData := val.Struct
		for fieldName, fieldData := range structData.GetFields() {
			// If field Data is primitive or primitiveList, then check it's key and redact if needed
			if spec_util.IsPrimitive(fieldData) || spec_util.IsPrimitiveList(fieldData) {
				if s.obfuscationOptions.SensitiveDataKeys.Contains(strings.ToLower(fieldName)) {
					ObfuscatePrimitiveWithRedactedString(fieldData)
				}
			} else {
				// Recursively traverse the struct's fields.
				childCtx := ctx.EnterStruct(structData, fieldName).(vis.SpecVisitorContext)
				s.traverseAndRedactSensitiveInfo(childCtx, fieldData)
			}
		}
	case *pb.Data_List:
		listData := val.List
		if items := listData.GetElems(); items != nil {
			for i, itemData := range items {
				// Step through each item in the list and traverse the data node.
				// This list will never be primitive list, as primitive list is handled above.
				childCtx := ctx.EnterArray(listData, i).(vis.SpecVisitorContext)
				s.traverseAndRedactSensitiveInfo(childCtx, itemData)
			}
		}
	}
}

// Obfuscate the given primitive data with REDACTED string.
// In case of a primitive value repalce with REDACTED string and in case of a primitive list replace
// with a new list having single element, i.e., REDACTED string, to maintain the list structure.
func ObfuscatePrimitiveWithRedactedString(d *pb.Data) Cont {
	if spec_util.IsPrimitive(d) {
		dv := d.GetPrimitive()
		dv.Value = spec_util.NewPrimitiveString("REDACTED").Value
	}

	if spec_util.IsPrimitiveList(d) {
		dl := d.GetList()
		dl.Elems = make([]*pb.Data, 0)
		dl.Elems = append(dl.Elems, &pb.Data{
			Value: &pb.Data_Primitive{
				Primitive: spec_util.NewPrimitiveString("REDACTED"),
			},
		})
	}

	return Continue
}
