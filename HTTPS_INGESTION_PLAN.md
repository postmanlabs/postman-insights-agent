# HTTPS Traffic Ingestion & Upload Implementation Plan

## Status: IN PROGRESS
**Last Updated**: 2025-12-03
**Branch**: `feature/https-containerd-discovery`

## Executive Summary
Switch eCapture from text mode to **pcapng mode** and integrate per-pod file readers into apidump processes. This reuses existing `NetworkTrafficParser` infrastructure for maximum reliability and performance.

## Architecture: Per-Pod File Readers

### Why Per-Pod Files Work
- Each eCapture process hooks a **container-specific libssl path**: `/run/containerd/.../containerA/rootfs/usr/lib/libssl.so.3`
- Only processes in that container use that specific file (mount namespace isolation)
- Therefore each eCapture already captures **only that pod's traffic**
- No IP-based routing needed!

### Performance Analysis
- **Current**: N pods → N eCapture processes → N files
- **Proposed**: N pods → N file readers (one per apidump process)
- **Complexity**: O(N) - linear, simple, no routing overhead
- **vs Shared Router**: O(packets) routing + IP lookup overhead saved

### Traffic Flow
```
Pod A (Service X, API Key 1)
  ↓
eCapture A → containerA.pcapng
  ↓
Apidump A reads file → NetworkTrafficParser → Upload with Key 1
```

## Implementation Checklist

### ✅ Phase 1: eCapture PCAPNG Output (COMPLETED)
- [x] Modify `ecapture_manager.go` to use `-m pcap -w <file>` flags
- [x] Change file extension from `.txt` to `.pcapng`
- [x] Remove manual file handle management (eCapture handles it)
- [x] Update logging to reflect pcapng format

**Files Modified**:
- `cmd/internal/kube/daemonset/ecapture_manager.go`

**Commit**: (pending)

---

### 🔄 Phase 2: File Capture Infrastructure (IN PROGRESS)
- [ ] Create `pcap/file_capture.go` with `fileCaptureReader` implementation
- [ ] Implement continuous file polling (tail -f style)
- [ ] Handle EOF and file reopening for new packets

**Implementation Details**:
```go
type fileCaptureReader struct {
    filePath string
}

func (f *fileCaptureReader) capturePackets(...) (<-chan gopacket.Packet, error) {
    handle, err := pcap.OpenOffline(f.filePath)
    // ... poll for new packets as file grows
}
```

---

### ⏳ Phase 3: PodArgs and Apidump Integration (PENDING)
- [ ] Add `HTTPSCaptureFile` field to `PodArgs` struct
- [ ] Store file path in `kube_events_worker.go` after starting eCapture
- [ ] Pass file path to `apidump.Args` in `apidump_process.go`
- [ ] Add `HTTPSCaptureFile optionals.Optional[string]` to `apidump.Args`

**Files to Modify**:
- `cmd/internal/kube/daemonset/pod_args.go`
- `cmd/internal/kube/daemonset/kube_events_worker.go`
- `cmd/internal/kube/daemonset/apidump_process.go`
- `apidump/apidump.go`

---

### ⏳ Phase 4: Apidump File Collection (PENDING)
- [ ] Modify `apidump.go` `Run()` function to spawn HTTPS file collector
- [ ] Create backend collector for HTTPS traffic (same config as interface collectors)
- [ ] Apply same filtering pipeline (sampling, path/host filters, etc.)
- [ ] Spawn goroutine calling `pcap.Collect()` with file reader
- [ ] Increment `doneWG` and `numCollectors` for HTTPS collector

**Integration Point** (`apidump/apidump.go` line ~906):
```go
// After interface collectors setup
if httpsFile, exists := args.HTTPSCaptureFile.Get(); exists {
    printer.Infof("Starting HTTPS file capture from: %s\n", httpsFile)

    // Create HTTPS collector (same as interface collectors)
    httpsCollector = trace.NewBackendCollector(...)
    httpsCollector = &trace.PacketCountCollector{...}
    // ... apply filters

    doneWG.Add(1)
    numCollectors++
    go func() {
        defer doneWG.Done()
        pcap.Collect(..., "https-capture", ..., httpsCollector, ...)
    }()
}
```

---

### ⏳ Phase 5: Testing and Validation (PENDING)
- [ ] Build and deploy updated agent
- [ ] Verify `.pcapng` files created in `/tmp/ecapture-output/`
- [ ] Verify apidump logs show "Starting HTTPS file capture"
- [ ] Verify HTTPS traffic uploaded to backend
- [ ] Verify correct service attribution (API key/project ID)
- [ ] Verify no duplicate traffic (HTTP vs HTTPS)

**Test Commands**:
```bash
# Check pcapng files
kubectl exec agent-pod -- ls -lh /tmp/ecapture-output/

# Check apidump integrated file reader
kubectl logs agent-pod | grep "HTTPS file capture"

# Verify uploads
# Check Postman backend trace contains GitHub/Google HTTPS requests
```

---

## Technical Decisions

### Why PCAPNG Format?
- **gopacket native support**: `pcap.OpenOffline()` reads pcapng directly
- **Standard format**: Well-tested, battle-proven packet capture format
- **Reuse existing parsers**: `NetworkTrafficParser` already handles pcap input
- **No custom parsing**: Avoid writing eCapture text format parser

### Why Per-Pod Files (Not Shared Router)?
- **Simpler architecture**: No routing logic, no IP lookups
- **Container isolation**: eCapture only captures traffic from specific container
- **Correct attribution**: Each file belongs to one pod/service
- **Performance**: O(N) scaling, no routing overhead
- **Maintainability**: Follows existing patterns (one apidump per pod)

### HTTP vs HTTPS Traffic
| Traffic Type | Network Interface | eCapture File | Result |
|-------------|-------------------|---------------|---------|
| HTTP (port 80) | ✅ Captured & parsed | ❌ Not captured | Uploaded via interface collector |
| HTTPS (port 443) | ✅ Captured but encrypted | ✅ Captured & decrypted | Uploaded via file collector |
| **Duplication?** | **Encrypted = can't parse** | **Decrypted = parsed** | **NO DUPLICATION** |

---

## File Polling Strategy

### Current Approach: Naive Reopen
```go
for {
    select {
    case <-done:
        return
    case pkt, ok := <-pktChan:
        if !ok {
            // EOF reached
            time.Sleep(100 * time.Millisecond)
            // Reopen file to check for new packets
            continue
        }
        wrappedChan <- pkt
    }
}
```

### Future Optimization (if needed):
- **inotify-based file watching** (Linux): More efficient than polling
- **gopacket streaming API**: Check if supports tail-f natively
- **File rotation**: Handle large files by rotating periodically

---

## Files Modified/Created

### Modified Files (7)
1. ✅ `cmd/internal/kube/daemonset/ecapture_manager.go` - Switch to pcap mode
2. ⏳ `cmd/internal/kube/daemonset/pod_args.go` - Add HTTPSCaptureFile field
3. ⏳ `cmd/internal/kube/daemonset/kube_events_worker.go` - Store file path
4. ⏳ `cmd/internal/kube/daemonset/apidump_process.go` - Pass to apidump
5. ⏳ `apidump/apidump.go` - Add file collector in Run()
6. ⏳ `pcap/net_parse.go` - (Optional) Support custom reader

### New Files (2)
7. ⏳ `pcap/file_capture.go` - File reader implementation
8. ✅ `HTTPS_INGESTION_PLAN.md` - This document

**Estimated Total LOC**: ~250-350 lines

---

## Potential Issues & Mitigations

### 1. File Polling Performance
**Issue**: Naive file reopening is inefficient
**Mitigation**: Implement inotify-based file watching if needed (profile first)

### 2. File Growth
**Issue**: Pcapng files grow unbounded
**Mitigation**: Implement file rotation in eCapture manager or rely on pod lifecycle

### 3. Timing Lag
**Issue**: File reads lag behind real-time capture
**Mitigation**: Acceptable for trace collection (not real-time monitoring)

### 4. gopacket File Reading
**Issue**: `OpenOffline()` might not support continuous reading
**Mitigation**: Test with growing files, implement polling if needed

---

## Success Criteria

1. ✅ eCapture writes `.pcapng` files instead of `.txt`
2. ⏳ Apidump spawns file reader goroutine
3. ⏳ `NetworkTrafficParser` successfully parses HTTPS packets from file
4. ⏳ HTTPS requests/responses uploaded to Postman backend
5. ⏳ Correct service attribution (each pod uploads with its API key)
6. ⏳ No duplicate traffic (HTTP from interface, HTTPS from file)
7. ⏳ Performance acceptable (no memory leaks, reasonable CPU usage)

---

## Next Steps

1. Complete `pcap/file_capture.go` implementation
2. Add `HTTPSCaptureFile` to `PodArgs` and propagate to apidump
3. Integrate file collector into `apidump.Run()`
4. Build, deploy, and test end-to-end
5. Create user-facing documentation (HTTPS_CAPTURE.md)

---

## References

- **eCapture docs**: https://ecapture.cc
- **gopacket**: https://pkg.go.dev/github.com/google/gopacket
- **Previous attempt**: `versilis/ecapture` branch (shared router approach)
- **Related files**:
  - `pcap/pcap_replay_test.go:151` - Example `filePcapWrapper`
  - `pcap/net_parse.go:93` - `NewNetworkTrafficParser`
  - `apidump/apidump.go:906` - Collector setup in `Run()`
