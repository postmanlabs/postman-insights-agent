# `ebpf/`: HTTPS capture

This package captures decrypted HTTPS traffic with eBPF: uprobes on `libssl`, and syscall tracepoints that read the frames the Java agent writes.
The design is in [`docs/https-capture-design.md`](../docs/https-capture-design.md); this file is for building and testing it.

## Build tags

The eBPF code builds only on Linux with the `insights_bpf` tag, which needs the `bpf2go` output.

| Build | Result |
|---|---|
| Default (`go build .`, every platform) | Stubs. `--enable-https-capture` warns that this build has no HTTPS capture and runs without it. |
| `-tags insights_bpf` on Linux | The real code. Needs the generated `ebpf/loader/*_bpfel.go` and `*.o`. |
| `-tags insights_bpf` on macOS | Does not build. Use the dev container. |

`make` adds the tag by itself on a Linux host with `clang` and `bpftool`; `make test` never compiles tagged code.
How the BPF programs are compiled, and `vmlinux.h`, are described in [`programs/README.md`](programs/README.md).

## Building

### macOS, through the dev container

`build-scripts/dev-container.sh` runs a privileged Debian container (`pia-bpf-dev`) with Go, clang and bpftool, the repository at `/workspace`, and the host's `/proc` at `/host/proc`, on Docker Desktop's kernel.

```sh
make dev-build        # once: build the dev image
make generate-ebpf    # vmlinux.h and the bpf2go output, into your tree
make dev-shell        # a shell in the container; `make` there builds with eBPF
make docker-build-ebpf  # or: a static eBPF binary in bin/, without a shell
```

`make generate-ebpf` is also what gopls needs when `.vscode/settings.json` enables the `insights_bpf` tag (otherwise it reports `undefined: libsslObjects`); reload the editor afterwards.

### Linux, natively

With `clang` 14 or newer, `llvm-strip`, `bpftool` and `libbpf-dev`:

```sh
make   # generates vmlinux.h and the bpf2go output, then builds with insights_bpf
sudo ./bin/postman-insights-agent apidump --enable-https-capture ...
```

### Images

- `build-scripts/Dockerfile.ebpf`: the agent with eBPF and the Java capture files in `/opt/postman` (built by `build-scripts/java-capture-files.sh`), as the DaemonSet runs it; the kind tests use it.
- `build-scripts/Dockerfile.ebpf-bin`: the static eBPF binary only (`make docker-build-ebpf`).

## Testing

- `make test`: every package without the tag, so the eBPF code runs as stubs.
- `make test-ebpf`: `go test -tags insights_bpf -p 1 ./ebpf/...`, as root on Linux (the tests load real programs).
  `-p 1` matters: the Java tracepoints see every positional write on the host, so packages tested at the same time see each other's frames.
  In the dev container: `build-scripts/dev-container.sh run 'make test-ebpf'`.
- The real-JVM tests (`TestNodeCollectorJVM*`) also need a JDK, the Java agent jar and the test apps; they skip without them.
  See "Building and testing" in [`java-agent/README.md`](../java-agent/README.md).
- End to end in kind: `test/kind/deploy-java-service.sh` (Java, through the production DaemonSet path) and [`test/kind/SERVICE-TEST-GUIDE.md`](../test/kind/SERVICE-TEST-GUIDE.md) (Node.js and .NET).

## Package layout

| Path | What it holds |
|---|---|
| `collect*.go` | `Collect`, the pipeline for one capture (`apidump`), and `ErrUnsupported` |
| `node_collector*.go`, `sub.go` | `NodeCollector`: one program set per node, events routed to per-pod subscriptions |
| `libraries.go` | `--https-libraries` names and defaults |
| `ratecap_linux.go`, `thermostat_linux.go` | sampling layers 2 (per-PID rate cap) and 5 (CPU thermostat) |
| `preresolve_linux.go`, `java_control_linux.go` | address pre-resolution for OpenSSL, the Java agents' control-file contents |
| `programs/` | BPF C sources: `libssl.bpf.c`, `java_tls.bpf.c` and their headers |
| `loader/` | loads the programs (`bpf2go` bindings), maps and counters |
| `events/` | ring-buffer reader, event decoding, the adapter to akinet (HTTP/1.1, HTTP/2), the socket resolver |
| `uprobes/` | finds `libssl` (shared or linked into the executable) and attaches the uprobes |
| `discovery/` | polls `/proc` for processes with `libssl` and for JVMs; maps pods to network namespaces through the CRI |
| `javatls/` | the contract with the Java agent: frames, control file, HEARTBEAT, file names (kept in sync with the kernel and Java copies by tests) |
| `jvm/` | JVM detection, control files, attaching the Java agent to running JVMs, removing other versions' copies |
| `jvm/attach/` | the HotSpot attach protocol, run as each JVM's user by `cmd/postman-insights-jvm-attach` |
