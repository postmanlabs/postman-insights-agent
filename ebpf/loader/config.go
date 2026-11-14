package loader

// Config holds load-time configuration for the BPF programs. These values
// override the `volatile const` knobs declared in libssl.bpf.c.
type Config struct {
	// EnforcePIDAllowlist, when true, restricts uprobes to PIDs explicitly
	// added to the target_pids map. When false, all PIDs that hit the probe
	// are traced.
	EnforcePIDAllowlist bool

	// MaxCaptureBytes is the maximum number of plaintext bytes copied per
	// event. Clamped to MAX_EVENT_PAYLOAD (16384) at the BPF level. Power
	// of two recommended for verifier-friendly masking.
	MaxCaptureBytes uint32

	// EnableJava also loads the Java TLS programs (java_tls.bpf.c), which
	// read the frames the Postman Insights Java agent writes. A failure to load or
	// attach them disables only Java capture: Load still succeeds and reports
	// the failure through Loader.JavaError.
	EnableJava bool

	// EnforceJavaNetnsAllowlist, when true, accepts Java frames only from
	// network namespaces added with Loader.AllowJavaNetns. When false, frames
	// from every process are accepted.
	EnforceJavaNetnsAllowlist bool

	// javaReadHookKprobe, for tests, attaches the tcp_recvmsg and
	// tcp_sendmsg hooks with kprobes even where fexit and fentry work, as on
	// kernels without BPF trampolines.
	javaReadHookKprobe bool

	// javaNoAppendRejected, for tests, skips pwritev2 calls with
	// RWF_NOAPPEND as on kernels before 6.9, which reject the flag.
	javaNoAppendRejected bool
}

// Default returns the default load config: no PID allowlist enforcement,
// 16 KiB capture per event.
func Default() Config {
	return Config{
		EnforcePIDAllowlist: false,
		MaxCaptureBytes:     16384,
	}
}

func (c Config) bpfEnforce() uint32 {
	if c.EnforcePIDAllowlist {
		return 1
	}
	return 0
}

func (c Config) bpfEnforceJavaNetns() uint32 {
	if c.EnforceJavaNetnsAllowlist {
		return 1
	}
	return 0
}

func (c Config) bpfMaxCapture() uint32 {
	if c.MaxCaptureBytes == 0 {
		return 16384
	}
	return c.MaxCaptureBytes
}
