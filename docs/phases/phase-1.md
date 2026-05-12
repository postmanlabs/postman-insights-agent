# Phase 1 — Spike: OpenSSL HTTPS → existing pipeline

**Starting branch:** `feat/https-capture-ebpf` at the commit titled
`ebpf: Phase 1 scaffold — libssl uprobes → akinet pipeline`.

**Working branch:** `feat/https-capture-ebpf-phase1`.

**Requires:** A Linux host or VM with kernel ≥ 5.8, `clang ≥ 14`, `llvm-strip`, `bpftool`, root or `CAP_BPF`+`CAP_PERFMON`. Cannot be completed on macOS.

---

## Goal

End-to-end: decrypted HTTP/1.1 bytes from an OpenSSL-using process reach `trace.Collector.Process()` as an `akinet.HTTPRequest`/`akinet.HTTPResponse`, indistinguishable from what `pcap.Collect` produces today.

## Hard exit criteria

All three must be demonstrable on a Linux box:

1. `curl -k https://localhost/` against a local nginx with HTTPS produces one `akinet.HTTPRequest{Method:"GET", URL:...}` and one `akinet.HTTPResponse{StatusCode:200}` in the spike command's stdout.
2. A Python script using `requests.get("https://example.com/")` produces the same.
3. A Node.js script using `https.get(...)` produces the same.

Plus performance:

4. CPU overhead of the agent ≤ 5% at 1000 RPS HTTPS load against a single nginx on a 4-core box. Measure with `pidstat -p $(pgrep postman-insights-agent) 1` for 60s.

## Prerequisites — read these first

In the agent repo:
- `docs/https-capture-design.md` §§ 4.1, 5.1–5.2, 6.1–6.2, 9 (Phase 1)
- `ebpf/README.md` — package status table
- `ebpf/programs/libssl.bpf.c` — the BPF C source
- `ebpf/loader/loader_linux.go` — bpf2go invocation site
- `ebpf/events/adapter.go` — note the `TODO(phase2)` markers; **Phase 1 leaves those alone** and uses a simpler stdout-dump in the spike command
- `cmd/internal/apidump-ebpf/run_linux.go` — the spike entry point

In OBI (`../insights-ebpf-research/obi/`):
- `bpf/generictracer/libssl.c` lines 1–264 — what our `libssl.bpf.c` is adapted from
- `pkg/internal/ebpf/generictracer/generictracer_linux.go` — cilium/ebpf load pattern
- `Makefile` — clang invocation arguments

## Tasks (in order)

### 1. Get the BPF program compiling

```sh
# On the Linux build host:
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h
echo "vmlinux.h" >> ebpf/programs/.gitignore     # do not commit per-arch headers

go install github.com/cilium/ebpf/cmd/bpf2go@v0.18.0   # pin version
cd ebpf/loader && go generate ./...
```

Expected outputs in `ebpf/loader/`:
- `libssl_bpfel.go`, `libssl_bpfel.o` (little-endian, x86_64 + arm64)
- `libssl_bpfeb.go`, `libssl_bpfeb.o` (big-endian — generated but unused on our targets)

**Delete `ebpf/loader/libssl_generated_stub.go` if it still exists** — it has been removed but if a prior session re-introduced it, it will conflict with the bpf2go output.

Commit the generated `.go` and `.o` files. Yes, commit them — they need to be in the binary via `//go:embed`. Update `.gitignore` for `vmlinux.h` only.

### 2. Add cilium/ebpf as a Go dependency

```sh
go get github.com/cilium/ebpf@v0.18.0
go get golang.org/x/sys@latest
go mod tidy
```

Verify build:
```sh
go build -tags insights_bpf ./...
```

### 3. Fix the verifier complaints

The BPF verifier will reject the program on first load. Most likely failures and fixes:

| Error | Cause | Fix |
|---|---|---|
| `R1 invalid mem access 'inv'` | Using a map lookup result without NULL check | Already handled in `libssl.bpf.c` — verify your edits didn't break this. |
| `unbounded memory access` on `bpf_probe_read_user` | `to_copy` not provably ≤ PAYLOAD size | The mask `to_copy &= (MAX_EVENT_PAYLOAD - 1)` should handle this. If verifier still complains, add an explicit `if (to_copy > MAX_EVENT_PAYLOAD) return 0;` before the mask. |
| `BPF_FUNC_probe_read_user not found` | Kernel < 5.5 | Check kernel version; we floor at 5.8. |
| `unknown func bpf_ringbuf_reserve` | Kernel < 5.8 | Same. |

Iterate by running the spike binary with `-v=4` and reading the verifier log dumped on `*ebpf.VerifierError`.

### 4. Smoke-test the loader

Write a one-off test (`ebpf/loader/loader_linux_test.go`, build-tag-gated) that:

```go
//go:build linux && insights_bpf
package loader

func TestLoadLibssl(t *testing.T) {
    if os.Geteuid() != 0 { t.Skip("requires root") }
    l, err := Load(Default())
    require.NoError(t, err)
    require.NotNil(t, l.EventsMap())
    require.NotNil(t, l.TargetPIDsMap())
    require.NoError(t, l.Close())
}
```

Run: `sudo -E go test -tags insights_bpf -run TestLoadLibssl ./ebpf/loader/`

### 5. End-to-end spike validation

Set up a target. Easiest:

```sh
docker run -d --name nginx-https -p 443:443 \
    -v $(pwd)/test/certs:/etc/nginx/certs \
    nginx:latest   # configure nginx for HTTPS on 443

# Get the nginx worker PID for verification
NGINX_PID=$(docker inspect -f '{{.State.Pid}}' nginx-https)
```

Build and run the spike:
```sh
go build -tags insights_bpf -o bin/postman-insights-agent .
sudo ./bin/postman-insights-agent apidump-ebpf --duration 60s --max-capture-bytes 1024
```

In another shell:
```sh
for i in $(seq 1 100); do curl -sk https://localhost/ > /dev/null; done
```

You should see ≥ 100 lines of `REQ method=GET ...` and `RESP status=200 ...` in the spike's stdout.

If nothing appears: check `dmesg` for verifier errors, check `cat /sys/kernel/debug/tracing/trace_pipe` for `bpf_dbg_printk` output (uncomment the debug prints in `libssl.bpf.c` if needed).

### 6. CPU measurement

```sh
# Generate sustained load
wrk -t 4 -c 50 -d 60s https://localhost/

# Measure agent CPU in parallel
pidstat -p $(pgrep -f apidump-ebpf) 1 60 > /tmp/cpu.log

# Average %CPU column should be < 5% for a 4-core box at ~1000 RPS.
```

If overhead is over budget, first suspect:
- `max_capture_bytes` is too high (reduce to 256 and retest)
- The stdout dumper is the bottleneck — pipe to `/dev/null` and remeasure
- Map sizes too small (active_ssl_read_args / active_ssl_write_args max_entries) causing thrashing

### 7. Write a phase-1 results doc

Create `docs/phases/phase-1-results.md` with:
- Kernel version + distro tested on
- BPF object sizes (`ls -la ebpf/loader/libssl_bpfel.o`)
- Measured CPU% at 100/1000/10000 RPS
- Any deviations from the design doc
- Open questions for Phase 2

## Common failure modes

1. **`vmlinux.h` mismatch.** If you generate vmlinux.h on kernel X and run on kernel Y where struct layouts differ, BPF programs may panic or read garbage. CO-RE relocations *usually* handle this but not for every struct. Mitigation: rebuild vmlinux.h in the same container used to run the binary.

2. **Cgroup-namespaced /proc.** Inside a container, `/proc/<pid>/maps` may not show the host PIDs you expect. Run the spike on the host network namespace, or mount `/proc` from the host (the DaemonSet manifest in design doc §8.1 does this).

3. **Uprobe attach fails with "no such file or directory".** The `/proc/<pid>/root/...` path is only valid while the target PID is alive. Discovery polls every 5s by default — if the target restarts between scan and attach, you'll see this error. Non-fatal; the next scan picks it up.

4. **OpenSSL 1.x vs 3.x symbol differences.** OpenSSL 1.1 has `SSL_read`/`SSL_write`. OpenSSL 3.x adds `*_ex`. Our code handles both (`link.ErrNoSymbol` is non-fatal). Verify on both versions before declaring done.

5. **Statically-linked binaries (Node, Envoy) fail discovery.** Phase 1 only handles dynamic libssl. This is acceptable — call it out in the results doc and defer to Phase 2.

6. **`bpf_probe_read_user` returns -EFAULT.** The user buffer was swapped out or the process exited between probe entry and probe exit. We already silently drop these. If you see >1% of events failing this way, there's a real bug — likely a stale arg pointer.

## Validation

Before opening the PR back to `feat/https-capture-ebpf`:

```sh
# 1. Default build must still work everywhere.
go build ./...
go vet ./...

# 2. Real build on Linux.
go build -tags insights_bpf ./...

# 3. Existing tests pass.
make mock && go test ./...

# 4. eBPF-specific tests pass on Linux.
sudo -E go test -tags insights_bpf ./ebpf/...

# 5. The three end-to-end scenarios (curl, Python, Node) from exit criteria.

# 6. CPU budget met.
```

## Handoff to Phase 2

Update these files before merging:

- `ebpf/README.md` — flip the "current status" table entries to ✅.
- `docs/https-capture-design.md` — add a "Phase 1 results" callout in §9.
- `docs/phases/phase-2.md` — read the "Prerequisites from Phase 1" section there; confirm each item is true.

What Phase 2 will rely on from your work:
- The `events.SSLEvent` byte format and `FlowKey` triple are stable.
- The `ebpf.Collect` signature is stable.
- The verifier-friendly bound on `to_copy` is correct.
- Real measured throughput numbers exist so Phase 2 can size sampling correctly.
