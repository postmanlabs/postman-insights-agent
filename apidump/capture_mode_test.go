package apidump

import "testing"

func TestCaptureMode(t *testing.T) {
	tests := []struct {
		name    string
		hasPcap bool
		hasEBPF bool
		want    string
	}{
		{name: "pcap", hasPcap: true, want: "pcap"},
		{name: "ebpf", hasEBPF: true, want: "ebpf"},
		{name: "both", hasPcap: true, hasEBPF: true, want: "pcap_and_ebpf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := captureMode(tt.hasPcap, tt.hasEBPF); got != tt.want {
				t.Fatalf("captureMode() = %q, want %q", got, tt.want)
			}
		})
	}
}
