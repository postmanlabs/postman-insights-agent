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
	SensitiveDataValuePatterns []*regexp.Regexp
}

func NewObfuscator() *Obfuscator {
	// Load obfuscation config using relative path to load the config file.
	config, err := loadConfigFromFile()
	if err != nil {
		printer.Errorf("failed to load obfuscation config: %v\n", err)
		return nil
	}

	sensitiveDataRegex := make([]*regexp.Regexp, len(config.SensitiveValueRegexes))

	// Compile regex patterns.
	for i, pattern := range config.SensitiveValueRegexes {
		// Panic if any pattern in invalid. Since the list is not user driven and is part of the agent, this is acceptable.
		sensitiveDataRegex[i] = regexp.MustCompile(pattern)
	}

	return &Obfuscator{
		SensitiveDataKeys:          sets.NewSet(config.SensitiveKeys...),
		SensitiveDataValuePatterns: sensitiveDataRegex,
	}
}

func (o *Obfuscator) ObfuscateDataWithZeroValue(m *pb.Method) {
	var ov obfuscationVisitor
	vis.Apply(&ov, m)

	// Mark the method as obfuscated.
	m.GetMeta().GetHttp().Obfuscation = pb.HTTPMethodMeta_ZERO_VALUE
	return
}

type obfuscationVisitor struct {
	vis.DefaultSpecVisitorImpl
}

var _ vis.DefaultSpecVisitor = (*obfuscationVisitor)(nil)

// EnterData processes the given data and obfuscates all the primitive values with zero values, regardless of it's meta data.
func (*obfuscationVisitor) EnterData(self interface{}, _ vis.SpecVisitorContext, d *pb.Data) Cont {
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

type redactSensitiveInfoVisitor struct {
	vis.DefaultSpecVisitorImpl
	obfuscationOptions *Obfuscator
}

var _ vis.DefaultSpecVisitor = (*redactSensitiveInfoVisitor)(nil)

// EnterData processes the given data and obfuscates sensitive information based on the provided obfuscation options.
// It does 3 checks to determine if the data contains sensitive information:
// 1. It checks if spec is an HTTP Authorization or Cookie data and obfuscates the value.
// 2. It checks if spec is an HTTP Header or Query Param data and obfuscates the value if the key is in the list of sensitive keys.
// 3. It applies regex patterns to all obfuscate sensitive primitive string values.
func (s *redactSensitiveInfoVisitor) EnterData(self interface{}, _ vis.SpecVisitorContext, d *pb.Data) Cont {
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

	for _, pattern := range s.obfuscationOptions.SensitiveDataValuePatterns {
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
	s.traverseAndRedactSensitiveInfo(data, false)

	return Continue
}

func (s *redactSensitiveInfoVisitor) EnterHTTPMultipart(self interface{}, ctx vis.SpecVisitorContext, mp *pb.HTTPMultipart) Cont {
	node, _ := ctx.GetInnermostNode(reflect.TypeOf((*pb.Data)(nil)))
	data := node.(*pb.Data)
	if data == nil {
		return Continue
	}

	// Traverse the data node and redact sensitive information.
	s.traverseAndRedactSensitiveInfo(data, false)

	return Continue
}

// Traverses the protobuf data and redacts sensitive information based on the sensitive keys.
// The function has 2 parameters:
//  1. data: The current node in the recursive tree traversal of the protobuf data.
//  2. redactData: A boolean flag to indicate if the data should be redacted irrespective of it's key and value.
//     This will be true when the parent node is a sensitive key.
//
// The function checks if the data fields are primitive and redacts them if their keys are sensitive.
// For non-primitive fields, it recursively traverses it's child nodes with the redactData flag set to true if the parent node is sensitive.
func (s *redactSensitiveInfoVisitor) traverseAndRedactSensitiveInfo(data *pb.Data, redactData bool) {
	switch val := data.Value.(type) {
	case *pb.Data_Primitive:
		if redactData {
			ObfuscatePrimitiveWithRedactedString(data)
		}
	case *pb.Data_Struct:
		// Traverse the struct's fields and redact sensitive information based on key.
		structData := val.Struct
		for fieldName, fieldData := range structData.GetFields() {
			// Check if the key is sensitive. If it is, redact the child data.
			redactData := redactData || s.obfuscationOptions.SensitiveDataKeys.Contains(strings.ToLower(fieldName))
			s.traverseAndRedactSensitiveInfo(fieldData, redactData)
		}
	case *pb.Data_List:
		listData := val.List
		if items := listData.GetElems(); items != nil {
			for _, itemData := range items {
				// Step through each item in the list and traverse the data node.
				s.traverseAndRedactSensitiveInfo(itemData, redactData)
			}
		}
	default:
		// Unknown data type, mark as REDACTED string.
		printer.Errorf("Unknown data type '%v' found, marking as REDACTED string\n", reflect.TypeOf(data.Value).String())
		ObfuscatePrimitiveWithRedactedString(data)
	}
}

// Obfuscate the given primitive data with REDACTED string.
// In case data is not primitive type, it will also be marked as REDACTED string.
func ObfuscatePrimitiveWithRedactedString(d *pb.Data) Cont {
	redactedPrimitiveString := spec_util.NewPrimitiveString("REDACTED")

	if dp := d.GetPrimitive(); dp != nil {
		dp.Value = redactedPrimitiveString.Value
	} else {
		// Unknown data type captured, though this should not happen,except in case of OneOf and Optionals which should also not be present.
		// Mark the data as REDACTED  string.
		printer.Debugf("Unknown data type found, marking as REDACTED string\n")
		d.Value = &pb.Data_Primitive{Primitive: redactedPrimitiveString}
	}

	return Continue
}
