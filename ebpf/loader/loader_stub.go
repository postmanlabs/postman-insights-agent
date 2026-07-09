// SPDX-License-Identifier: Apache-2.0
//
// Stub Loader for builds without the `insights_bpf` tag, and for non-Linux
// platforms. Returns ErrUnsupported from Load(); all accessor methods return
// nil so callers can structure code defensively without per-call build tags.

//go:build !linux || !insights_bpf

package loader

import "errors"

// ErrUnsupported is returned by Load() when this binary was compiled without
// eBPF support (no `insights_bpf` build tag, or non-Linux target).
var ErrUnsupported = errors.New("ebpf: HTTPS capture not compiled into this binary (build with -tags insights_bpf on Linux)")

// Loader is a no-op stub on platforms / builds without eBPF.
type Loader struct{}

func Load(_ Config) (*Loader, error) { return nil, ErrUnsupported }

func (*Loader) Close() error { return nil }

// The accessor methods return interface{}-typed nil. The real Linux loader
// returns *ebpf.Map / *ebpf.Program, but callers compiled without the
// insights_bpf tag never reach those code paths (they short-circuit on
// ErrUnsupported from Load).
//
// We use `any` to avoid pulling cilium/ebpf into the dependency graph for
// non-eBPF builds.
func (*Loader) EventsMap() any                          { return nil }
func (*Loader) TargetPIDsMap() any                      { return nil }
func (*Loader) CountersMap() any                        { return nil }
func (*Loader) SSLReadProgs() (entry, exit any)         { return nil, nil }
func (*Loader) SSLReadExProgs() (entry, exit any)       { return nil, nil }
func (*Loader) SSLWriteProgs() (entry, exit any)        { return nil, nil }
func (*Loader) SSLWriteExProgs() (entry, exit any)      { return nil, nil }
func (*Loader) SSLSetFDProg() any                       { return nil }
func (*Loader) SSLFreeProg() any                        { return nil }
func (*Loader) ReadCounter(_ uint32) (uint64, error)    { return 0, ErrUnsupported }
func (*Loader) SetMaxCaptureBytes(_ uint32) error       { return ErrUnsupported }
func (*Loader) GetMaxCaptureBytes() (uint32, error)     { return 0, ErrUnsupported }
func (*Loader) RateBucketsMap() any                     { return nil }
func (*Loader) SSLFdMap() (any, bool)                   { return nil, false }
func (*Loader) SetRateCapPerSec(_ uint32) error         { return ErrUnsupported }
func (*Loader) RefillRateBucket(_ uint32, _ uint64) error { return ErrUnsupported }
func (*Loader) DeleteRateBucket(_ uint32) error         { return ErrUnsupported }
func OpenExecutable(_ string) (any, error)              { return nil, ErrUnsupported }

// Counter index constants (mirrored from loader_linux.go) so non-eBPF builds
// can still compile against the same call sites.
const (
	CounterEventsEmitted uint32 = 0
	CounterEventsDropped uint32 = 1
	CounterReadFailed    uint32 = 2
	CounterBytesCaptured uint32 = 3
)
