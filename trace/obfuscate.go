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

const redactionString = "*REDACTED*"

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

// Replaces all primitive values in the given method with zero values.
func (o *Obfuscator) ZeroAllPrimitivesInMethod(m *pb.Method) {
	var ov zeroPrimitivesVisitor
	vis.Apply(&ov, m)

	// Mark the method as obfuscated.
	m.GetMeta().GetHttp().Obfuscation = pb.HTTPMethodMeta_ZERO_VALUE
}

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

func (o *Obfuscator) RedactSensitiveData(m *pb.Method) {
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

// EnterData processes the given data and obfuscates sensitive information based
// on the provided obfuscation options. It does 3 checks to determine if the
// data contains sensitive information:
//
// 1. It checks if spec is an HTTP Authorization or Cookie data and obfuscates
// the value.
//
// 2. It checks if spec is an HTTP Header or Query Param data and obfuscates the
// value if the key is in the list of sensitive keys.
//
// 3. It applies regex patterns to all obfuscate sensitive primitive string
// values.
func (s *redactSensitiveInfoVisitor) EnterData(self interface{}, ctx vis.SpecVisitorContext, d *pb.Data) Cont {
	// Redact cookies and authorization headers.
	switch ctx.GetValueType() {
	case vis.AUTH, vis.COOKIE:
		redactPrimitivesInIR(d)
		return SkipChildren
	}

	if p := d.GetPrimitive(); p != nil {
		// We have a primitive value. Redact if the value is sensitive. Otherwise,
		// fall through and redact based on the field name.
		if s.primitiveHasSensitiveValue(p) {
			redactPrimitive(p)
			return SkipChildren
		}
	}

	// If a field name indicates that it is sensitive, redact its value.
	fieldPath := ctx.GetFieldPath()
	if len(fieldPath) > 0 {
		innermostFieldPathElt := fieldPath[len(fieldPath)-1]
		if innermostFieldPathElt.IsFieldName() {
			fieldName := innermostFieldPathElt.String()
			if s.obfuscationOptions.SensitiveDataKeys.Contains(strings.ToLower(fieldName)) {
				redactPrimitivesInIR(d)
				return SkipChildren
			}
		}
	}

	return Continue
}

func (s *redactSensitiveInfoVisitor) EnterHTTPMethodMeta(self interface{}, ctx vis.SpecVisitorContext, meta *pb.HTTPMethodMeta) Cont {
	pathSegments := strings.Split(meta.PathTemplate, "/")

	for i, segment := range pathSegments {
		// Check if the path segment contains sensitive information.
		if s.isSensitiveString(segment) {
			pathSegments[i] = redactionString
		}
	}

	meta.PathTemplate = strings.Join(pathSegments, "/")
	return SkipChildren
}

// Determines whether the given string is a sensitive value.
func (s *redactSensitiveInfoVisitor) isSensitiveString(v string) bool {
	for _, pattern := range s.obfuscationOptions.SensitiveDataValuePatterns {
		if pattern.MatchString(v) {
			return true
		}
	}
	return false
}

// Determines whether the given Primitive has a sensitive value.
func (s *redactSensitiveInfoVisitor) primitiveHasSensitiveValue(p *pb.Primitive) bool {
	sv := p.GetStringValue()
	if sv == nil {
		// Only strings can be sensitive.
		return false
	}

	return s.isSensitiveString(sv.Value)
}

func redactPrimitivesInIR[nodeT any](node nodeT) {
	var v redactPrimitivesVisitor
	vis.Apply(&v, node)
}

type redactPrimitivesVisitor struct {
	vis.DefaultSpecVisitorImpl
}

var _ vis.DefaultSpecVisitor = (*redactPrimitivesVisitor)(nil)

// If the Data being visited is a Primitive, it is replaced with the redaction
// string.
func (*redactPrimitivesVisitor) EnterData(self interface{}, _ vis.SpecVisitorContext, d *pb.Data) Cont {
	dp := d.GetPrimitive()
	if dp == nil {
		return Continue
	}

	redactPrimitive(dp)
	return SkipChildren
}

// Replaces the value in the given Primitive with the redaction string.
func redactPrimitive(p *pb.Primitive) {
	p.Value = spec_util.NewPrimitiveString(redactionString).Value
}
