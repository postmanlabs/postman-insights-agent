// SPDX-License-Identifier: Apache-2.0

package loader

// Config holds load-time configuration for the BPF programs. These values
// override the `volatile const` knobs declared in libssl.bpf.c.
type Config struct {
	// EnforcePIDAllowlist, when true, restricts uprobes to PIDs explicitly
	// added to the target_pids map. When false, all PIDs that hit the probe
	// are traced.
	EnforcePIDAllowlist bool

	// MaxCaptureBytes is the maximum number of plaintext bytes copied per
	// event. Clamped to MAX_EVENT_PAYLOAD (4096) at the BPF level. Power
	// of two recommended for verifier-friendly masking.
	MaxCaptureBytes uint32
}

// Default returns the default load config: no PID allowlist enforcement,
// 4 KiB capture per event.
func Default() Config {
	return Config{
		EnforcePIDAllowlist: false,
		MaxCaptureBytes:     4096,
	}
}

func (c Config) bpfEnforce() uint32 {
	if c.EnforcePIDAllowlist {
		return 1
	}
	return 0
}

func (c Config) bpfMaxCapture() uint32 {
	if c.MaxCaptureBytes == 0 {
		return 4096
	}
	return c.MaxCaptureBytes
}
