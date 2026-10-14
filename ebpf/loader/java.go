// SPDX-License-Identifier: Apache-2.0

package loader

// Java TLS counter indices. They must match JAVA_CTR_* in
// programs/java_tls.bpf.c.
const (
	JavaCounterFramesSeen       uint32 = 0 // writes at the magic offset
	JavaCounterEventsEmitted    uint32 = 1 // ring buffer submits
	JavaCounterEventsDropped    uint32 = 2 // ring buffer full
	JavaCounterReadFailed       uint32 = 3 // bpf_probe_read_user failed
	JavaCounterBytesCaptured    uint32 = 4 // sum of captured payload bytes
	JavaCounterRateCapped       uint32 = 5 // dropped by the per-PID rate cap
	JavaCounterNetnsRejected    uint32 = 6 // sender not in an allowed netns
	JavaCounterMalformed        uint32 = 7 // failed validation
	JavaCounterControlFrames    uint32 = 8 // HEARTBEAT and CLOSE frames
	JavaCounterHeartbeatLimited uint32 = 9 // HEARTBEATs over the per-PID limit
)
