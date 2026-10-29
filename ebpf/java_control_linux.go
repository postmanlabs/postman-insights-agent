// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
)

// javaControl is what the Java agents' control files say: capture while the
// Java programs are loaded, with the kernel's current payload cap (lowered by
// the thermostat under load), so agents copy no more than the kernel keeps.
func javaControl(requested bool, l *loader.Loader, therm *Thermostat, maxCaptureBytes uint32) javatls.Control {
	limit := maxCaptureBytes
	if therm != nil {
		if c := therm.CurrentCap(); c > 0 {
			limit = c
		}
	}
	if limit == 0 || limit > javatls.DefaultCaptureCap {
		limit = javatls.DefaultCaptureCap
	}
	return javatls.Control{
		Enabled:    requested && l.JavaEnabled(),
		CaptureCap: int(limit),
	}
}
