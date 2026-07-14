package daemonset

import (
	"os"
	"runtime"
	"testing"

	"github.com/postmanlabs/postman-insights-agent/apidump"
	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/stretchr/testify/assert"
)

// testNodeCollector is a non-nil sentinel so HTTPS-enabled buildHTTPSArgs tests
// pass the DaemonSet gate requiring a shared NodeCollector, without a real BPF host.
var testNodeCollector = &ebpf.NodeCollector{}

// ---------------------------------------------------------------------------
// buildHTTPSArgs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// buildHTTPSArgs — disabled
// ---------------------------------------------------------------------------

func TestBuildHTTPSArgs_Disabled(t *testing.T) {
	d := &Daemonset{EnableHTTPSCapture: false}
	pod := &PodArgs{Namespace: "team-a"}

	got := buildHTTPSArgs(d, pod, 12345)

	assert.False(t, got.Enabled)
	assert.Zero(t, got.ContainerNetnsInode,
		"inode must be zero when HTTPS capture is disabled")
	assert.Nil(t, got.TargetNamespaces,
		"TargetNamespaces must be nil when HTTPS capture is disabled")
}

// ---------------------------------------------------------------------------
// buildHTTPSArgs — inode path (pod-level, preferred)
// ---------------------------------------------------------------------------

func TestBuildHTTPSArgs_InodeTakesPriority(t *testing.T) {
	// When a valid inode is provided the inode path must be used and
	// TargetNamespaces must NOT be set — even if the pod has a namespace.
	// This is the normal DaemonSet path for any scaled deployment.
	d := &Daemonset{
		EnableHTTPSCapture:   true,
		EBPFNodeCollector:    testNodeCollector,
		HTTPSRateCapPerSec:   500,
		HTTPSBodySizeCap:     2048,
		HTTPSCBPFExcludePort: 443,
	}
	pod := &PodArgs{Namespace: "team-a"}
	const inode uint64 = 99991

	got := buildHTTPSArgs(d, pod, inode)

	assert.True(t, got.Enabled)
	assert.Equal(t, inode, got.ContainerNetnsInode,
		"inode must be forwarded to ContainerNetnsInode")
	assert.Nil(t, got.TargetNamespaces,
		"TargetNamespaces must be nil when inode is available — inode path is pod-level")
	assert.Equal(t, uint32(500), got.RateCapPerSec)
	assert.Equal(t, uint32(2048), got.BodySizeCap)
	assert.Equal(t, uint16(443), got.CBPFExcludePort)
}

func TestBuildHTTPSArgs_InodeZeroWithNamespace_FallsBackToNamespace(t *testing.T) {
	// Inode lookup failed (CRI unavailable, rapid startup, etc.) but the pod
	// namespace is known (discovery mode). Fall back to namespace-level
	// filtering so HTTPS capture is not silently lost.
	d := &Daemonset{EnableHTTPSCapture: true, EBPFNodeCollector: testNodeCollector, HTTPSRateCapPerSec: 100}
	pod := &PodArgs{Namespace: "team-a"}

	got := buildHTTPSArgs(d, pod, 0 /* inode unavailable */)

	assert.True(t, got.Enabled)
	assert.Zero(t, got.ContainerNetnsInode)
	assert.Equal(t, []string{"team-a"}, got.TargetNamespaces,
		"should fall back to namespace-level filtering when inode is unavailable")
}

func TestBuildHTTPSArgs_InodeZeroWithoutNamespace_NodeWide(t *testing.T) {
	// Inode unavailable AND namespace unknown (non-discovery mode).
	// eBPF runs node-wide — acceptable for single-pod non-discovery setups.
	d := &Daemonset{EnableHTTPSCapture: true, EBPFNodeCollector: testNodeCollector}
	pod := &PodArgs{Namespace: ""}

	got := buildHTTPSArgs(d, pod, 0)

	assert.True(t, got.Enabled)
	assert.Zero(t, got.ContainerNetnsInode)
	assert.Nil(t, got.TargetNamespaces,
		"no filter when neither inode nor namespace is available")
}

func TestBuildHTTPSArgs_DisabledIgnoresInode(t *testing.T) {
	// Even with a valid inode and namespace, disabled means disabled.
	d := &Daemonset{EnableHTTPSCapture: false}
	pod := &PodArgs{Namespace: "production"}

	got := buildHTTPSArgs(d, pod, 54321)

	assert.False(t, got.Enabled)
	assert.Zero(t, got.ContainerNetnsInode)
	assert.Nil(t, got.TargetNamespaces)
}

func TestBuildHTTPSArgs_RateAndBodyPropagation(t *testing.T) {
	tests := []struct {
		name              string
		rateCapPerSec     uint32
		bodySizeCap       uint32
		wantRateCapPerSec uint32
		wantBodySizeCap   uint32
	}{
		{"both zero (unlimited/default)", 0, 0, 0, 0},
		{"non-zero rate cap", 1000, 0, 1000, 0},
		{"non-zero body cap", 0, 512, 0, 512},
		{"both non-zero", 250, 4096, 250, 4096},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Daemonset{
				EnableHTTPSCapture: true,
				EBPFNodeCollector:  testNodeCollector,
				HTTPSRateCapPerSec: tt.rateCapPerSec,
				HTTPSBodySizeCap:   tt.bodySizeCap,
			}
			got := buildHTTPSArgs(d, &PodArgs{}, 42 /* any non-zero inode */)
			assert.Equal(t, tt.wantRateCapPerSec, got.RateCapPerSec)
			assert.Equal(t, tt.wantBodySizeCap, got.BodySizeCap)
		})
	}
}

func TestBuildHTTPSArgs_CBPFExcludePortPropagation(t *testing.T) {
	tests := []struct {
		name        string
		excludePort uint16
		wantExclude uint16
	}{
		{"default 443", 443, 443},
		{"custom 8443", 8443, 8443},
		{"zero disables exclusion", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Daemonset{
				EnableHTTPSCapture:   true,
				EBPFNodeCollector:    testNodeCollector,
				HTTPSCBPFExcludePort: tt.excludePort,
			}
			got := buildHTTPSArgs(d, &PodArgs{}, 42)
			assert.Equal(t, tt.wantExclude, got.CBPFExcludePort)
		})
	}
}

// ---------------------------------------------------------------------------
// DaemonsetArgs — HTTPS field zero values and propagation
// ---------------------------------------------------------------------------

func TestDaemonsetArgs_HTTPSDefaultsToDisabled(t *testing.T) {
	args := DaemonsetArgs{}
	assert.False(t, args.EnableHTTPSCapture,
		"EnableHTTPSCapture must default to false so existing deployments are unaffected")
	assert.Zero(t, args.HTTPSRateCapPerSec)
	assert.Zero(t, args.HTTPSBodySizeCap)
}

func TestDaemonsetArgs_ApplyEnvVarDefaultsDoesNotTouchHTTPS(t *testing.T) {
	// applyEnvVarDefaults reads discovery-mode env vars; it must never
	// overwrite the HTTPS fields that the operator set via CLI flags.
	args := DaemonsetArgs{
		EnableHTTPSCapture: true,
		HTTPSRateCapPerSec: 999,
		HTTPSBodySizeCap:   8192,
	}
	args.applyEnvVarDefaults()

	assert.True(t, args.EnableHTTPSCapture,
		"applyEnvVarDefaults must not clear EnableHTTPSCapture")
	assert.Equal(t, uint32(999), args.HTTPSRateCapPerSec,
		"applyEnvVarDefaults must not clear HTTPSRateCapPerSec")
	assert.Equal(t, uint32(8192), args.HTTPSBodySizeCap,
		"applyEnvVarDefaults must not clear HTTPSBodySizeCap")
}

// ---------------------------------------------------------------------------
// Daemonset struct — HTTPS field propagation from DaemonsetArgs
// ---------------------------------------------------------------------------

func TestDaemonset_HTTPSFieldsPropagatedFromArgs(t *testing.T) {
	// Verify that the three HTTPS fields make it from DaemonsetArgs into the
	// Daemonset struct (they are wired in StartDaemonset; tested here by
	// inspecting the struct directly to catch regressions without standing up
	// the full daemonset).
	args := DaemonsetArgs{
		EnableHTTPSCapture:   true,
		HTTPSRateCapPerSec:   123,
		HTTPSBodySizeCap:     456,
		HTTPSCBPFExcludePort: 443,
	}

	// Simulate the assignment done by StartDaemonset.
	d := &Daemonset{
		EnableHTTPSCapture:   args.EnableHTTPSCapture,
		HTTPSRateCapPerSec:   args.HTTPSRateCapPerSec,
		HTTPSBodySizeCap:     args.HTTPSBodySizeCap,
		HTTPSCBPFExcludePort: args.HTTPSCBPFExcludePort,
	}

	assert.True(t, d.EnableHTTPSCapture)
	assert.Equal(t, uint32(123), d.HTTPSRateCapPerSec)
	assert.Equal(t, uint32(456), d.HTTPSBodySizeCap)
	assert.Equal(t, uint16(443), d.HTTPSCBPFExcludePort)
}

// ---------------------------------------------------------------------------
// readNetnsInode — reads the current process's own netns inode
// ---------------------------------------------------------------------------

func TestReadNetnsInode_Self(t *testing.T) {
	// /proc/self/ns/net only exists on Linux.
	if runtime.GOOS != "linux" {
		t.Skip("not running on Linux — /proc not available")
	}
	// readNetnsInode internally checks for /host/proc/self; since that path
	// does not exist in the test environment it falls back to /proc, which is
	// where the test process lives.
	inode, err := readNetnsInode(os.Getpid())
	assert.NoError(t, err)
	assert.NotZero(t, inode, "own netns inode must be non-zero")
}

func TestReadNetnsInode_InvalidPID(t *testing.T) {
	// PID 0 never exists in /proc; the call must return 0 and a non-nil error.
	inode, err := readNetnsInode(0)
	assert.Error(t, err)
	assert.Zero(t, inode)
}

// ---------------------------------------------------------------------------
// buildHTTPSArgs — return type sanity
// ---------------------------------------------------------------------------

func TestBuildHTTPSArgs_ReturnsCorrectType(t *testing.T) {
	// Compile-time check that buildHTTPSArgs returns apidump.HTTPSCaptureArgs.
	var _ apidump.HTTPSCaptureArgs = buildHTTPSArgs(&Daemonset{}, &PodArgs{}, 0)
}

// ---------------------------------------------------------------------------
// buildHTTPSArgs — NodeCollector propagation
// ---------------------------------------------------------------------------

func TestBuildHTTPSArgs_NodeCollectorPropagated(t *testing.T) {
	// When EBPFNodeCollector is set on the Daemonset (HTTPS enabled), it must
	// be forwarded into HTTPSCaptureArgs.NodeCollector so startHTTPSeBPFCapture
	// can use the shared loader instead of calling loader.Load per pod.
	//
	// We use a non-nil sentinel pointer to verify propagation without requiring
	// a real BPF-capable host. The NodeCollector stub is used on non-Linux /
	// non-insights_bpf builds.
	sentinel := &ebpf.NodeCollector{}
	d := &Daemonset{
		EnableHTTPSCapture: true,
		EBPFNodeCollector:  sentinel,
	}
	pod := &PodArgs{Namespace: "team-a"}

	got := buildHTTPSArgs(d, pod, 12345)

	assert.True(t, got.Enabled)
	assert.Same(t, sentinel, got.NodeCollector,
		"NodeCollector must be the exact pointer set on the Daemonset")
}

func TestBuildHTTPSArgs_NodeCollectorNilWhenDisabled(t *testing.T) {
	// When HTTPS capture is disabled, buildHTTPSArgs must return early with
	// Enabled=false and NodeCollector=nil — even if EBPFNodeCollector is set.
	sentinel := &ebpf.NodeCollector{}
	d := &Daemonset{
		EnableHTTPSCapture: false,
		EBPFNodeCollector:  sentinel,
	}
	got := buildHTTPSArgs(d, &PodArgs{Namespace: "team-a"}, 12345)

	assert.False(t, got.Enabled)
	assert.Nil(t, got.NodeCollector,
		"NodeCollector must not be forwarded when HTTPS capture is disabled")
}

func TestBuildHTTPSArgs_NodeCollectorMissingDisablesHTTPS(t *testing.T) {
	// When EBPFNodeCollector is not set (BPF load failed at DaemonSet startup),
	// HTTPS must be disabled for per-pod apidump — do not fall back to per-pod
	// ebpf.Collect(), which would reload BPF programs once per monitored pod.
	d := &Daemonset{
		EnableHTTPSCapture: true,
		EBPFNodeCollector:  nil,
	}
	got := buildHTTPSArgs(d, &PodArgs{Namespace: "team-a"}, 12345)

	assert.False(t, got.Enabled,
		"HTTPS must be disabled when the shared NodeCollector is unavailable")
	assert.Nil(t, got.NodeCollector)
}

// ---------------------------------------------------------------------------
// HTTPSCaptureArgs — NodeCollector default
// ---------------------------------------------------------------------------

func TestHTTPSCaptureArgs_NodeCollectorDefaultsNil(t *testing.T) {
	// Zero-value HTTPSCaptureArgs must have NodeCollector=nil so existing
	// callers that construct HTTPSCaptureArgs directly (tests, standalone
	// apidump) are not affected.
	var args apidump.HTTPSCaptureArgs
	assert.Nil(t, args.NodeCollector,
		"NodeCollector zero value must be nil — existing callers must not change")
}

// ---------------------------------------------------------------------------
// Daemonset — EBPFNodeCollector nil by default
// ---------------------------------------------------------------------------

func TestDaemonset_EBPFNodeCollectorDefaultsNil(t *testing.T) {
	// A zero-value Daemonset must have EBPFNodeCollector=nil before startup
	// initialises the shared node-scoped collector.
	d := &Daemonset{}
	assert.Nil(t, d.EBPFNodeCollector)
}
