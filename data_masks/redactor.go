package data_masks

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/spec_util"
	. "github.com/akitasoftware/akita-libs/visitors"
	vis "github.com/akitasoftware/akita-libs/visitors/http_rest"
	"github.com/akitasoftware/go-utils/sets"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
)

const RedactionString = "*REDACTED*"

const dynamicConfigUpdateInterval = time.Minute

// W3C Trace Context headers that should always be preserved (never obfuscated).
// These headers are essential for distributed tracing and contain no sensitive data.
// See: https://www.w3.org/TR/trace-context/
var traceContextHeaders = sets.NewSet(
	"traceparent",
	"tracestate",
)

// Replaces sensitive data with a redaction string.
type Redactor struct {
	SensitiveDataKeys          sets.Set[string]
	SensitiveDataValuePatterns []*regexp.Regexp

	// The dynamic portion of the configuration. Periodically updated from the
	// back end.
	userConfig *userRedactionConfig

	// Style controls the replacement (RedactionString vs hash). Defaults to
	// StyleRedact (zero value of RedactionStyle is "" which parses to redact).
	Style RedactionStyle

	// PrivacyConfig is the resolved privacy-mode config. Empty struct = the
	// historical PrivacyStandard behaviour.
	PrivacyConfig PrivacyModeConfig

	// Coverage tracks per-rule redaction counts for telemetry. nil is safe
	// (the Inc* helpers no-op on nil).
	Coverage *CoverageCounters

	// When this channel is closed, it signals that the goroutine for updating
	// userConfig should exit.
	exitChannel chan struct{}

	// Ensures that exitChannel is closed at most once.
	closeExitChannelOnce *sync.Once
}

// Creates a redactor for the given service ID. Uses the given learn client to
// periodically update its dynamic configuration from the back end.
func NewRedactor(
	serviceID akid.ServiceID,
	learnClient rest.LearnClient,
) (*Redactor, error) {
	// Load redaction config using relative path to load the config file.
	config, err := loadConfigFromFile()
	if err != nil {
		printer.Errorf("failed to load redaction config: %v\n", err)
		return nil, errors.Wrapf(err, "unable to load redaction configuration")
	}

	sensitiveDataRegex := make([]*regexp.Regexp, len(config.SensitiveValueRegexes))

	// Compile regex patterns.
	for i, pattern := range config.SensitiveValueRegexes {
		// Panic if any pattern is invalid. Since the list is not user driven and is
		// part of the agent, this is acceptable.
		sensitiveDataRegex[i] = regexp.MustCompile(pattern)
	}

	// Obtain the latest dynamic configuration.
	dynamicConfig, err := learnClient.GetDynamicAgentConfigForService(context.TODO(), serviceID)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get dynamic agent configuration for %s", serviceID)
	}
	activeUserConfig := newUserRedactionConfig(dynamicConfig)

	exitChannel := make(chan struct{})

	// Periodically update the dynamic configuration.
	go func() {
		ticker := time.NewTicker(dynamicConfigUpdateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-exitChannel:
				return

			case <-ticker.C:
			}

			// Get the latest agent configuration.
			ctx, cancel := context.WithTimeout(
				context.Background(),
				dynamicConfigUpdateInterval/2,
			)
			newConfig, err := func() (*api_schema.ServiceAgentConfig, error) {
				defer cancel()
				return learnClient.GetDynamicAgentConfigForService(
					ctx,
					serviceID,
				)
			}()
			if err != nil {
				printer.Warningf("failed to update redaction configuration for %s: %v\n", serviceID, err)
				continue
			}

			// Update with the new configuration.
			activeUserConfig.update(newConfig)
		}
	}()

	return &Redactor{
		SensitiveDataKeys:          sets.NewSet(config.SensitiveKeys...),
		SensitiveDataValuePatterns: sensitiveDataRegex,
		userConfig:                 activeUserConfig,
		Style:                      StyleRedact,
		PrivacyConfig:              PrivacyStandard.Config(),
		Coverage:                   NewCoverageCounters(),
		exitChannel:                exitChannel,
		closeExitChannelOnce:       &sync.Once{},
	}, nil
}

// SetStyle replaces the redaction style. Must be called before any
// concurrent RedactSensitiveData invocations; not safe to change at
// runtime.
func (o *Redactor) SetStyle(s RedactionStyle) {
	o.Style = s
}

// SetPrivacyMode resolves the privacy-mode config and stores it. Must be
// called before any concurrent RedactSensitiveData invocations.
func (o *Redactor) SetPrivacyMode(m PrivacyMode) {
	o.PrivacyConfig = m.Config()
}

func (o *Redactor) StopPeriodicUpdates() {
	o.closeExitChannelOnce.Do(func() {
		close(o.exitChannel)
	})
}

func (o *Redactor) RedactSensitiveData(m *pb.Method) {
	o.userConfig.RLock()
	defer o.userConfig.RUnlock()

	o.Coverage.IncRequestScanned()

	pov := redactSensitiveInfoVisitor{
		redactionOptions: o,
	}
	vis.Apply(&pov, m)

	// Apply privacy-mode body/header dropping AFTER the standard
	// redaction pass. ZeroAllPrimitives produces a zero-typed value for
	// each primitive, which is what downstream type inference wants.
	if o.PrivacyConfig.DropBodies || len(o.PrivacyConfig.HeaderAllowlist) > 0 {
		pmv := privacyModeVisitor{
			redactor: o,
			dropBodies: o.PrivacyConfig.DropBodies,
			headerAllowed: o.PrivacyConfig.HeaderAllowed,
		}
		vis.Apply(&pmv, m)
	}
}

func (o *Redactor) ZeroAllPrimitives(m *pb.Method) {
	o.userConfig.RLock()
	defer o.userConfig.RUnlock()

	zpv := zeroPrimitivesVisitor{
		redactionOptions: o,
	}
	vis.Apply(&zpv, m)

	m.GetMeta().GetHttp().Obfuscation = pb.HTTPMethodMeta_ZERO_VALUE
}

// Determines whether fields with the given name should be redacted. Caller must
// hold at least a read lock on muUserConfig.
func (o *Redactor) redactFieldsNamed(fieldName string) bool {
	lc := strings.ToLower(fieldName)

	// Determine whether to redact based on default rules.
	if o.SensitiveDataKeys.Contains(lc) {
		o.Coverage.IncSensitiveKey(lc)
		return true
	}

	// Determine whether to redact based on user settings.
	if o.userConfig.redactFieldsNamed(fieldName) {
		o.Coverage.IncUserRule(lc)
		return true
	}

	return false
}

// styledReplacement returns the appropriate replacement for the redactor's
// configured style. Centralises the choice so callers don't have to know
// about RedactionStyle.
func (o *Redactor) styledReplacement(orig string) string {
	if o == nil {
		return RedactionString
	}
	return applyRedactionStyle(orig, o.Style)
}

type redactSensitiveInfoVisitor struct {
	vis.DefaultSpecVisitorImpl
	redactionOptions *Redactor
}

var _ vis.DefaultSpecVisitor = (*redactSensitiveInfoVisitor)(nil)

// EnterData processes the given data and redacts sensitive information based
// on the provided redaction options. It does 3 checks to determine if the
// data contains sensitive information:
//
// 1. It checks if spec is an HTTP Authorization or Cookie data and redacts
// the value.
//
// 2. It checks if spec is an HTTP Header or Query Param data and redacts the
// value if the key is in the list of sensitive keys.
//
// 3. It applies regex patterns to all redacts sensitive primitive string
// values.
func (s *redactSensitiveInfoVisitor) EnterData(self interface{}, ctx vis.SpecVisitorContext, d *pb.Data) Cont {
	// Redact cookies and authorization headers.
	switch ctx.GetValueType() {
	case vis.AUTH:
		s.redactionOptions.Coverage.IncSensitiveKey("authorization")
		redactPrimitivesInIR(d, s.redactionOptions)
		return SkipChildren
	case vis.COOKIE:
		s.redactionOptions.Coverage.IncSensitiveKey("cookie")
		redactPrimitivesInIR(d, s.redactionOptions)
		return SkipChildren
	}

	if p := d.GetPrimitive(); p != nil {
		// We have a primitive value. Redact if the value is sensitive. Otherwise,
		// fall through and redact based on the field name.
		if s.primitiveHasSensitiveValue(p) {
			redactPrimitive(p, s.redactionOptions)
			return SkipChildren
		}
	}

	// If a field name indicates that it is sensitive, redact its value.
	fieldPath := ctx.GetFieldPath()
	if len(fieldPath) > 0 {
		innermostFieldPathElt := fieldPath[len(fieldPath)-1]
		if innermostFieldPathElt.IsFieldName() {
			fieldName := innermostFieldPathElt.String()
			if s.redactionOptions.redactFieldsNamed(fieldName) {
				redactPrimitivesInIR(d, s.redactionOptions)
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
			pathSegments[i] = RedactionString
		}
	}

	meta.PathTemplate = strings.Join(pathSegments, "/")
	return SkipChildren
}

// Determines whether the given string is a sensitive value.
func (s *redactSensitiveInfoVisitor) isSensitiveString(v string) bool {
	for i, pattern := range s.redactionOptions.SensitiveDataValuePatterns {
		if pattern.MatchString(v) {
			s.redactionOptions.Coverage.IncSensitiveRegex(fmt.Sprintf("builtin[%d]", i))
			return true
		}
	}
	if s.redactionOptions.userConfig.redactStringRegex(v) {
		s.redactionOptions.Coverage.IncUserRule("value_regex")
		return true
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

// redactPrimitivesInIR walks node and replaces every leaf primitive with
// the redactor's configured replacement.
func redactPrimitivesInIR(node interface{}, r *Redactor) {
	v := redactPrimitivesVisitor{redactor: r}
	vis.Apply(&v, node)
}

type redactPrimitivesVisitor struct {
	vis.DefaultSpecVisitorImpl
	redactor *Redactor
}

var _ vis.DefaultSpecVisitor = (*redactPrimitivesVisitor)(nil)

// If the Data being visited is a Primitive, it is replaced with the
// redactor's configured replacement (fixed string or hash token).
func (v *redactPrimitivesVisitor) EnterData(self interface{}, _ vis.SpecVisitorContext, d *pb.Data) Cont {
	dp := d.GetPrimitive()
	if dp == nil {
		return Continue
	}
	redactPrimitive(dp, v.redactor)
	return SkipChildren
}

// redactPrimitive replaces the value in the given Primitive with the
// redactor's configured replacement.
func redactPrimitive(p *pb.Primitive, r *Redactor) {
	orig := ""
	if sv := p.GetStringValue(); sv != nil {
		orig = sv.Value
	}
	p.Value = spec_util.NewPrimitiveString(r.styledReplacement(orig)).Value
}

// Replaces all primitive values with zero values.
type zeroPrimitivesVisitor struct {
	vis.DefaultSpecVisitorImpl
	redactionOptions *Redactor
}

var _ vis.DefaultSpecVisitor = (*zeroPrimitivesVisitor)(nil)

// isTraceContextHeader checks if the given data represents a W3C trace context header.
// Returns true if this is a traceparent or tracestate header that should be preserved.
func isTraceContextHeader(d *pb.Data) bool {
	header := spec_util.HTTPHeaderFromData(d)
	if header == nil {
		return false
	}
	return traceContextHeaders.Contains(strings.ToLower(header.GetKey()))
}

// EnterData processes the given data and replaces all the primitive values
// with zero values, regardless of its metadata.
// Exception: W3C trace context headers (traceparent, tracestate) are preserved
// to enable distributed tracing correlation.
func (*zeroPrimitivesVisitor) EnterData(self interface{}, _ vis.SpecVisitorContext, d *pb.Data) Cont {
	dp := d.GetPrimitive()
	if dp == nil {
		return Continue
	}

	// Preserve W3C trace context headers - these are essential for distributed
	// tracing and contain no sensitive user data.
	if isTraceContextHeader(d) {
		return SkipChildren
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

func (s *zeroPrimitivesVisitor) EnterHTTPMethodMeta(self interface{}, ctx vis.SpecVisitorContext, meta *pb.HTTPMethodMeta) Cont {
	pathSegments := strings.Split(meta.PathTemplate, "/")

	for i, segment := range pathSegments {
		// Check if the path segment contains sensitive information.
		if s.isSensitiveString(segment) {
			pathSegments[i] = RedactionString
		}
	}

	meta.PathTemplate = strings.Join(pathSegments, "/")
	return SkipChildren
}

func (s *zeroPrimitivesVisitor) isSensitiveString(v string) bool {
	for i, pattern := range s.redactionOptions.SensitiveDataValuePatterns {
		if pattern.MatchString(v) {
			s.redactionOptions.Coverage.IncSensitiveRegex(fmt.Sprintf("builtin[%d]", i))
			return true
		}
	}
	if s.redactionOptions.userConfig.redactStringRegex(v) {
		s.redactionOptions.Coverage.IncUserRule("value_regex")
		return true
	}
	return false
}

// privacyModeVisitor implements the PrivacyStrict body-drop / header-
// allowlist behaviour. It runs AFTER the sensitive-key + regex pass so
// the per-rule counters reflect what the redactor saw; the drops here
// are a separate, coarser layer.
type privacyModeVisitor struct {
	vis.DefaultSpecVisitorImpl
	redactor      *Redactor
	dropBodies    bool
	headerAllowed func(string) bool
}

var _ vis.DefaultSpecVisitor = (*privacyModeVisitor)(nil)

// EnterData zeroes body primitives (when dropBodies is set) and drops
// non-allowlisted headers (when headerAllowed is set).
func (v *privacyModeVisitor) EnterData(self interface{}, ctx vis.SpecVisitorContext, d *pb.Data) Cont {
	dp := d.GetPrimitive()
	if dp == nil {
		return Continue
	}

	switch ctx.GetValueType() {
	case vis.BODY:
		if v.dropBodies {
			pv, err := spec_util.PrimitiveValueFromProto(dp)
			if err == nil {
				dp.Value = pv.Obfuscate().ToProto().Value
				v.redactor.Coverage.IncBodyDropped()
			}
			return SkipChildren
		}
	case vis.HEADER:
		// Only filter headers when an allowlist is configured.
		if v.headerAllowed == nil {
			return Continue
		}
		fieldPath := ctx.GetFieldPath()
		if len(fieldPath) == 0 {
			return Continue
		}
		// The header name is typically the second-to-last path element
		// (the last is the value primitive itself). Be defensive.
		var headerName string
		for i := len(fieldPath) - 1; i >= 0; i-- {
			if fieldPath[i].IsFieldName() {
				headerName = fieldPath[i].String()
				break
			}
		}
		if headerName == "" {
			return Continue
		}
		if !v.headerAllowed(headerName) {
			pv, err := spec_util.PrimitiveValueFromProto(dp)
			if err == nil {
				dp.Value = pv.Obfuscate().ToProto().Value
				v.redactor.Coverage.IncHeaderDropped()
			}
			return SkipChildren
		}
	}
	return Continue
}
