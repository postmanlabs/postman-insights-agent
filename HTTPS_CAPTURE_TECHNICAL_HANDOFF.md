# HTTPS Capture - Technical Handoff & Completion Roadmap

**Date:** January 12, 2026
**Branch:** `feature/https-containerd-discovery`
**Status:** Proof-of-concept working for OpenSSL only
**Engineer:** Versilis Tyson

---

## Executive Summary

This document provides a complete technical handoff for the HTTPS capture feature built on eCapture (eBPF-based SSL/TLS interception). The current implementation successfully captures HTTPS traffic from **Python services using OpenSSL**, but has critical limitations that prevent production deployment.

**Key takeaway:** This is a partially working prototype. Completing this feature for production requires significant additional work (8-12 weeks estimate) and clear product requirements around language/framework support.

---

## Current State & Test Coverage

### ✅ What's Confirmed Working

- **Python + OpenSSL services** (tested with Front service in beta)
  - SSL library discovery via filesystem scanning
  - eCapture process launch in text mode
  - HTTP/2 HEADERS and DATA frame parsing
  - Request/response witness generation and backend ingestion
  - Successfully captured outbound HTTPS API calls in minikube and beta

- **Infrastructure**
  - Multi-architecture Docker images (AMD64/ARM64)
  - eCapture v0.8.6 bundled in agent image
  - Kubernetes DaemonSet with required privileges (hostPID, privileged mode, eBPF capabilities)
  - Containerd filesystem access for scanning container rootfs

### ❌ What's Known Broken

**See "Critical Blockers" section below for detailed breakdown.**

---

## Architecture Overview

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  Kubernetes Pod (Any Namespace)                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Application Process                                        │ │
│  │  ├─ OpenSSL (libssl.so)  ← hooked by eCapture              │ │
│  │  ├─ Go crypto/tls        ← NOT SUPPORTED YET               │ │
│  │  └─ Java (javax.net.ssl) ← CANNOT BE SUPPORTED             │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│  Postman Insights Agent (DaemonSet Pod on same node)            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  1. Pod Event Listener (kube_events_worker.go)             │ │
│  │     • Watches pod creation/deletion via Kubernetes API     │ │
│  │     • Triggers SSL library scanning for new pods           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                           ↓                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  2. SSL Library Scanner (ssl_scanner.go)                   │ │
│  │     • Reads container filesystem via containerd mount      │ │
│  │     • Path: /run/containerd/.../rootfs/{containerID}       │ │
│  │     • Searches for libssl.so in /lib, /usr/lib, etc.       │ │
│  │     • Returns: LibraryPaths, LibraryType (openssl/go/etc)  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                           ↓                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  3. eCapture Manager (ecapture_manager.go)                 │ │
│  │     • Launches: /ecapture tls --libssl=<path> -m text      │ │
│  │     • One eCapture process per pod (keyed by containerID)  │ │
│  │     • Captures stdout via pipe (NEVER writes to disk)      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                           ↓                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  4. Text Reader (ecapture_text_reader.go)                  │ │
│  │     • Reads eCapture stdout line-by-line                   │ │
│  │     • Buffers lines into logical frames                    │ │
│  │     • Emits RawFrame structs via channel                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                           ↓                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  5. Text Parser (text_parser.go)                           │ │
│  │     • Detects protocol: HTTP/1.1 vs HTTP/2                 │ │
│  │     • Parses HTTP/2 HEADERS frames → ParsedRequest         │ │
│  │     • Parses HTTP/2 DATA frames → ParsedDataFrame          │ │
│  │     • Parses HTTP/1.1 requests/responses                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                           ↓                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  6. Text Collector (text_collector.go)                     │ │
│  │     • Tracks HTTP/2 streams by stream ID                   │ │
│  │     • Pairs requests with responses                        │ │
│  │     • Converts to Witness (Postman's internal format)      │ │
│  │     • Sends to backend ingestion pipeline                  │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Key File Structure

```
postman-insights-agent/
├── cmd/internal/kube/daemonset/
│   ├── daemonset.go              # Main entry point for DaemonSet mode
│   ├── kube_events_worker.go     # Watches pod create/delete events
│   ├── ssl_scanner.go            # Discovers SSL libraries in containers
│   ├── ecapture_manager.go       # Manages eCapture subprocess lifecycle
│   └── apidump_process.go        # Legacy pcap-based capture (still used for HTTP)
│
├── pcap/
│   ├── ecapture_text_reader.go   # Buffers eCapture stdout into frames
│   ├── text_parser.go            # Parses HTTP/1.1 and HTTP/2 text frames
│   ├── text_collector.go         # Converts frames to witnesses
│   ├── pcap.go                   # Legacy pcap-based capture
│   └── stream.go                 # TCP stream reassembly (legacy)
│
└── Dockerfile / Makefile         # Build configuration

observability-superstar-service/
└── cli-postman/
    ├── Dockerfile.cli.native     # Production image with eCapture binary
    └── Makefile                  # Cross-compilation targets

akita-infrastructure/
└── modules/insights_agent_mns/
    └── main.tf                   # Kubernetes DaemonSet definition
```

---

## Critical Blockers (Must Fix for Production)

### Blocker #1: Go TLS Not Supported (HIGH PRIORITY)

**Impact:** Most backend services at Postman (kings-cross, timeline-builder, etc.) are written in Go.

**Problem:**
- Go uses `crypto/tls` package, which does NOT link against OpenSSL
- Current SSL scanner only looks for OpenSSL libraries (`libssl.so`)
- eCapture supports Go via `ecapture gotls` mode, but it's not implemented in our code

**Current Code Issue (ssl_scanner.go:114-118):**
```go
if goExecutable := detectGoExecutable(rootfsPath); goExecutable != "" {
    info.LibraryType = "go"
    info.LibraryPaths = []string{goExecutable}  // BUG: Returns /usr/bin/go (compiler)
}
```
This searches for the Go compiler (`/usr/bin/go`), not the actual application binary (e.g., `/app/kings-cross`).

**What Needs to Happen:**
1. Fix Go binary detection:
   - Option A: Search `/proc/<pid>/exe` for all PIDs in container's cgroup
   - Option B: Parse container metadata (ENTRYPOINT/CMD from image config)
   - Option C: Search common app paths (`/app`, `/usr/local/bin`) for ELF binaries

2. Add `gotls` mode to ecapture_manager.go:
   ```go
   if sslInfo.LibraryType == "go" {
       cmd = exec.CommandContext(ctx, "/ecapture", "gotls",
           "--elfpath="+sslInfo.LibraryPaths[0],  // Path to Go binary
           "-m", "text",
       )
   }
   ```

3. Test with Go services (kings-cross in minikube, then beta)

**Effort Estimate:** 3-4 weeks
- 1 week: Research and implement Go binary detection
- 1 week: Add gotls mode and integration testing
- 1 week: Test in minikube with sample Go app
- 0.5-1 week: Deploy to beta and verify with real services

**Open Questions for Product:**
- Which Go services are priority for HTTPS capture? (e.g., kings-cross, timeline-builder)
- Do our Go binaries include debug symbols? (eCapture may require them)
- Are we okay with higher overhead for Go capture? (gotls mode is less efficient than OpenSSL hooking)

---

### Blocker #2: Java and Other Languages Cannot Be Supported (FUNDAMENTAL LIMITATION)

**Impact:** Services using Java, Ruby (with native TLS), or other languages that don't use OpenSSL or Go's crypto/tls.

**Problem:**
eCapture (and eBPF in general) works by hooking specific SSL library functions:
- **Supported:** OpenSSL (`SSL_read`, `SSL_write`), BoringSSL, Go crypto/tls
- **NOT Supported:** Java's `javax.net.ssl` (uses JVM-internal TLS implementation)

**Why Java Doesn't Work:**
- Java's TLS is implemented in the JVM itself, not via shared libraries
- eBPF cannot hook into JVM internals (would require JVM instrumentation)
- Even if we could hook the JVM, the data structures are completely different

**Testing Status:**
- ✅ **Tested and working:** Python (OpenSSL)
- ✅ **Tested and confirmed broken:** Go (not implemented, but eCapture supports it)
- ❌ **Not tested:** Node.js, Ruby, Rust, Java, .NET, PHP, Elixir

**What Needs to Happen:**
1. **Product decision required:** Create a language support matrix
   - Which languages are in scope for HTTPS capture?
   - What percentage of services use each language?
   - What's our fallback for unsupported languages?

2. **Testing plan for other languages:**
   - Node.js: Should work (uses OpenSSL), but needs testing (~1 week)
   - Ruby: Depends on Ruby version (may use OpenSSL or native TLS) (~1 week)
   - Rust: Depends on TLS library (rustls vs openssl crate) (~1 week)
   - Java: Won't work, need alternative approach (see below)

3. **Alternative for Java (if needed):**
   - Option A: Kernel-level SSL inspection (complex, requires mTLS handling)
   - Option B: JVM agent instrumentation (separate project, 8+ weeks)
   - Option C: Accept that Java HTTPS won't be captured

**Effort Estimate:** 4-6 weeks (language testing only, excluding Java alternatives)

**Critical Questions for Product:**
- **What languages are in production at Postman?** Provide breakdown by service count.
- **What's the priority order?** If we can only support 3 languages, which ones?
- **What's the minimum viable language support?** Can we ship with just Python + Go?
- **Is Java HTTPS capture a hard requirement?** If yes, this is a separate 3-month project.

---

### Blocker #3: HTTP/1.1 Pairing Not Implemented

**Impact:** Services that make HTTP/1.1 HTTPS calls (not HTTP/2) won't generate full request/response witnesses.

**Problem:**
- Current text_collector.go only pairs HTTP/2 requests/responses (via stream IDs)
- HTTP/1.1 doesn't have stream IDs, requires timing-based correlation
- HTTP/1.1 parsing is implemented in text_parser.go but collector doesn't handle it

**Symptoms:**
- HTTP/1.1 requests parsed successfully
- HTTP/1.1 responses parsed successfully
- But they're never paired into a single witness

**What Needs to Happen:**
1. Implement HTTP/1.1 pairing logic in text_collector.go:
   - Use timestamp + TCP connection (if available) to correlate
   - Handle pipelined requests (multiple in-flight on same connection)
   - Handle out-of-order responses (rare but possible)

2. Test with HTTP/1.1 client (curl without `--http2` flag)

**Effort Estimate:** 2-3 weeks
- 1 week: Design and implement pairing logic
- 1 week: Integration testing with various HTTP/1.1 scenarios
- 0.5-1 week: Fix edge cases (pipelining, keep-alive, etc.)

**Question for Product:**
- What percentage of services use HTTP/1.1 vs HTTP/2 for outbound calls?
- Can we ship with HTTP/2-only support initially?

---

### Blocker #4: SSL Library Discovery Flakiness

**Impact:** Some OpenSSL-based pods aren't detected correctly.

**Problem:**
- ssl_scanner.go searches common paths (`/lib`, `/usr/lib`, etc.)
- Doesn't handle all Linux distros (e.g., Alpine musl paths)
- Doesn't handle symlinks correctly (e.g., `libssl.so` → `libssl.so.3.0.7`)
- Doesn't retry on containerd mount timing issues

**What Needs to Happen:**
1. Expand search paths for Alpine, Debian, Ubuntu, RHEL variants
2. Follow symlinks to find actual library files
3. Add retry logic for containerd filesystem race conditions
4. Log detailed debugging info when no libraries found

**Effort Estimate:** 1-2 weeks

---

### Blocker #5: eCapture Process Stability

**Impact:** eCapture processes crash or hang, requiring restart logic.

**Current Status:**
- Basic restart logic exists (ecapture_manager.go:monitorProcess)
- But no health checks to detect hangs
- No circuit breaker to prevent restart loops

**What Needs to Happen:**
1. Implement health check: Ensure eCapture outputs data periodically
2. Add circuit breaker: Stop restarting after N failures
3. Add telemetry: Track eCapture restart rate

**Effort Estimate:** 1-2 weeks

---

## Timeline Estimates

### Scenario 1: Minimum Viable Product (Python + Go only)
**Goal:** Capture HTTPS from Python and Go services
**Effort:** 6-8 weeks
- Fix Go TLS support: 3-4 weeks
- Fix HTTP/1.1 pairing: 2-3 weeks
- Stabilization and testing: 1-2 weeks

**Confidence:** Medium (depends on Go binary detection complexity)

### Scenario 2: Production-Ready (Python, Go, Node.js)
**Goal:** Support top 3 languages at Postman
**Effort:** 10-12 weeks
- Scenario 1 work: 6-8 weeks
- Node.js testing and fixes: 1-2 weeks
- SSL discovery improvements: 1-2 weeks
- eCapture stability improvements: 1-2 weeks
- Beta testing and bug fixes: 1-2 weeks

**Confidence:** Medium-High

### Scenario 3: Full Language Support (Excluding Java)
**Goal:** Support all languages that use OpenSSL or Go crypto/tls
**Effort:** 14-16 weeks
- Scenario 2 work: 10-12 weeks
- Ruby, Rust, PHP testing: 2-3 weeks
- Edge case handling: 1-2 weeks

**Confidence:** Low (many unknowns in language-specific behavior)

### Scenario 4: Java Support (Separate Project)
**Goal:** Add Java JVM instrumentation
**Effort:** 12-16 weeks (separate from above)
- Research JVM agent approach: 2 weeks
- Implement JVM TLS hooks: 6-8 weeks
- Integration with agent: 2-3 weeks
- Testing and stabilization: 2-3 weeks

**Confidence:** Very Low (unproven approach)

---

## Product Questions That Need Answers

**Before continuing this work, product MUST provide:**

1. **Language Priority Matrix**
   - What languages are used in production? (by service count)
   - Which languages are in scope for HTTPS capture?
   - What's the priority order if we can't support all?

2. **Definition of "Done"**
   - What does "100% HTTPS capture" mean?
   - Is it:
     - A) Capture all HTTPS from any language?
     - B) Capture HTTPS from specific priority services?
     - C) Capture HTTPS from X% of services?
   - What's the minimum acceptable coverage to ship this feature?

3. **Java Requirements**
   - How many production services use Java?
   - Is Java HTTPS capture a hard requirement or nice-to-have?
   - If required, are we committing to 3+ months of additional work?

4. **Performance Expectations**
   - What's the acceptable overhead per pod?
   - Are we okay with higher overhead for Go services (gotls is slower)?
   - Should we filter by namespace/labels to reduce overhead?

5. **Failure Modes**
   - What happens if we can't capture HTTPS from a pod?
   - Silent fallback to HTTP-only? Or surface an error to users?

6. **Security and Compliance**
   - Are there any services where HTTPS capture is NOT allowed?
   - Do we need opt-in/opt-out per service?
   - How do we handle PII/secrets in decrypted traffic?

---

## Testing Checklist (Not Yet Done)

Before deploying to production, the following MUST be tested:

### Language Testing
- [ ] Python + OpenSSL (various versions: 1.x, 3.x)
- [ ] Go + crypto/tls (various Go versions: 1.18, 1.20, 1.21+)
- [ ] Node.js + OpenSSL
- [ ] Ruby (if in scope)
- [ ] Rust (if in scope)
- [ ] PHP (if in scope)
- [ ] Java (confirm it fails gracefully)

### Protocol Testing
- [ ] HTTP/2 over TLS (currently working)
- [ ] HTTP/1.1 over TLS (pairing not implemented)
- [ ] gRPC over TLS (should work via HTTP/2, but not tested)
- [ ] WebSockets over TLS (unknown)

### Infrastructure Testing
- [ ] Multi-node Kubernetes cluster (tested in beta, but flaky)
- [ ] Pod restarts (does eCapture restart correctly?)
- [ ] Agent restarts (does state recovery work?)
- [ ] High-traffic pods (performance impact?)
- [ ] Pods with no HTTPS traffic (silent failure?)

### Edge Cases
- [ ] Pods with multiple containers (which one to monitor?)
- [ ] Init containers (should be ignored?)
- [ ] Sidecar containers (e.g., Envoy proxies)
- [ ] Pods with custom base images (Alpine, distroless, etc.)
- [ ] Pods with no SSL libraries (graceful failure?)

---

## Known Issues (Unfixable or Low Priority)

### Issue: Incoming HTTPS Traffic Not Captured
**Why:** ALB/Ingress terminates TLS before traffic reaches pods
**Impact:** We can only capture outbound HTTPS calls, not incoming requests
**Status:** This is expected behavior, not a bug

### Issue: Architecture Mismatch (RESOLVED)
**Why:** Built ARM64 image on Mac, beta cluster runs AMD64
**Fix:** Multi-architecture Dockerfile now builds both AMD64 and ARM64
**Status:** Fixed in commit 138dcdd

---

## References

### Related PRs and Branches
- **postman-insights-agent:** `feature/https-containerd-discovery` (current branch)
- **observability-superstar-service:** `versilis/https-capture-rc`
- **akita-infrastructure:** `versilis/https-capture`

### External Documentation
- eCapture GitHub: https://github.com/gojue/ecapture
- eCapture Go TLS support: https://medium.com/@cfc4ncs/ecapture-supports-capturing-plaintext-of-golang-tls-https-traffic-f16874048269
- eBPF programming guide: https://ebpf.io/

### Key Commits
- `138dcdd` - Initial eCapture integration (text mode)
- `729356a` - Fixed security context for eBPF
- `469dc53` - Fixed container skip bug
- `727aa9a` - Added eCapture retry and stderr logging
- `bb4010f` - WIP (current HEAD)

---

## Contact and Handoff Notes

**Original Engineer:** Versilis Tyson (leaving company)
**Status:** This is a working prototype for OpenSSL-based Python services only. **Do not deploy to production without addressing the blockers above.**

**Next Steps for Whoever Picks This Up:**
1. Read this document thoroughly
2. Schedule a meeting with product to answer the "Product Questions" section
3. Based on product priorities, start with either:
   - **Scenario 1** (MVP: Python + Go) if you need something fast
   - **Scenario 2** (Production-ready) if you have 3 months
4. Set up a test environment with Go and Python services in minikube
5. Read the code in this order:
   - `cmd/internal/kube/daemonset/kube_events_worker.go` (entry point)
   - `cmd/internal/kube/daemonset/ssl_scanner.go` (start here for Go TLS fix)
   - `cmd/internal/kube/daemonset/ecapture_manager.go` (add gotls mode here)
   - `pcap/text_parser.go` (understand frame parsing)
   - `pcap/text_collector.go` (implement HTTP/1.1 pairing here)

**Good luck. This is hard but cool work.**
