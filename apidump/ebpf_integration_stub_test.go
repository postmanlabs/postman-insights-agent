//go:build !linux || !insights_bpf

package apidump

import (
	"testing"

	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/stretchr/testify/assert"
)

// Standalone, HTTPS capture does not run when the BPF programs cannot load:
// here, a build without eBPF.
func TestPrepareHTTPSCaptureStandaloneUnsupported(t *testing.T) {
	var a Args
	a.HTTPS.Enabled = true
	a.HTTPS.Libraries = ebpf.Libraries{OpenSSL: true}
	assert.Nil(t, prepareHTTPSCapture(&a))
}
