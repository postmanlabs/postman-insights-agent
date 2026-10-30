# HTTPS capture

How the Postman Insights Agent captures decrypted HTTPS traffic with eBPF, as built.
Users start from the "HTTPS capture" section of the [README](../README.md); developers build and test with [`ebpf/README.md`](../ebpf/README.md); the Java agent itself is described in [`java-agent/README.md`](../java-agent/README.md).

## 1. Overview

Classic BPF (libpcap) sees HTTPS only as TLS records, so the agent reads the plaintext where TLS libraries hold it: just before encryption and just after decryption.
HTTPS capture is opt-in (`--enable-https-capture`) and Linux-only; the macOS build captures HTTP only, and every eBPF path compiles to a no-op there.

| Runtime | How | Status |
|---|---|---|
| Processes using a shared `libssl` (C and C++, Python, Ruby, PHP, .NET, nginx, Node.js with the system OpenSSL) | uprobes on `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex` | Supported |
| Node.js with BoringSSL linked into `node` (official images) | the same uprobes, on the executable's own `SSL_*` symbols | Supported; verified on a bare Node 20 and in kind (`deploy-node-service.sh --static`) |
| Java on HotSpot, JDK 8 to 25: the JDK's `SSLEngine` and `SSLSocket`, Netty's OpenSSL engine (Tomcat, Jetty, Undertow, Netty, the JDK `HttpClient`, `HttpsURLConnection`) | a Java agent hands plaintext to the kernel (section 4) | Preview, on by default with `--enable-https-capture` |
| Go (`crypto/tls`), Rust (rustls), other JSSE providers' sockets (BouncyCastle, Conscrypt), OpenJ9 without `-javaagent` | - | Not supported |

## 2. Pipeline

```
libssl uprobes (libssl.bpf.c) ─┐
                               ├─► ring buffer ─► NodeCollector ─► events.Adapter ─► trace.Collector chain ─► backend
Java frames (java_tls.bpf.c) ──┘                  (routes by pod)   (akinet parsers)  (data_masks, rate limit)
```

- The eBPF events become the same `akinet.HTTPRequest` and `akinet.HTTPResponse` values that libpcap capture produces, and go through the same collector chain, redaction included.
- `events.Adapter` feeds each connection's bytes to the akinet HTTP/1.1 parsers, and HTTP/2 (for example gRPC over libssl) to its own stateful decoder (`ebpf/events/http2.go`), since HPACK state spans the connection.
- When HTTPS capture runs, libpcap leaves out TCP port 443 (`--https-cbpf-exclude-port`, 0 keeps it), so handshakes are not counted twice.
- Connection addresses: for OpenSSL, the agent maps each `SSL*` to its socket fd in the kernel and resolves the fd to its addresses from `/proc/<pid>/net/tcp{,6}`, ahead of time too, so connections that close quickly still resolve (`ebpf/events/resolver.go`, `ebpf/preresolve_linux.go`).
  Java connections get their addresses from the kernel (section 4).
  An event without either keeps zero addresses and names its PID in the interface field.

## 3. Deployment and scoping

- **DaemonSet (`kube run`):** one `NodeCollector` per node loads the programs once, owns the ring buffer, and fans events out to one subscription per monitored pod (`ebpf/node_collector_linux.go`).
  Events are routed by the pod's network-namespace inode, which the agent gets from the container runtime (CRI), because the PIDs the kernel reports do not match the agent's view on nested nodes (kind, k3d).
  Pods are chosen as for HTTP capture (namespaces, labels, the `postman.com/insights-disabled` annotation); see "Namespace opt-in: three independent layers" in [`discovery-mode.md`](discovery-mode.md).
- **Sidecar or single host (`apidump`):** OpenSSL capture attaches to every process the agent can see in `/proc`, unless `--https-target-namespaces` limits it to some Kubernetes namespaces (`ebpf/collect_linux.go`, `apidump/ebpf_integration.go`).
  With `hostPID`, which HTTPS capture needs, that is every process on the node, so a sidecar captures other pods' OpenSSL traffic too unless it is limited.
  Java capture is limited to the agent's own network namespace (section 4), and needs JVMs started with `-javaagent` there.

## 4. Java capture

The JVM implements TLS in Java, so there is no native symbol to probe.
A Java agent ([`java-agent/`](../java-agent/README.md)) hooks the TLS engines and sockets and writes each plaintext chunk as a frame with a positional write to `/dev/null`, at the magic offset `0x504D494E53494748` ("PMINSIGH").
The kernel program `ebpf/programs/java_tls.bpf.c`, on the `pwrite64`, `pwritev2` and `pwritev` syscall tracepoints, copies out writes at that offset, validates them and puts them into the same ring buffer as the libssl events.
`/dev/null` then discards the bytes, so the bridge needs no JNI or native code; the frame format is shared by the kernel, Go and Java copies described in the Java agent's README.

### Who may send frames

Any process can write at the magic offset, so the kernel accepts frames only from the network namespaces of monitored pods (the `java_netns` map), or the agent's own one for a sidecar, and validates every header.
A pod on the host network, or whose network namespace is unknown, is captured without Java, since its namespace does not identify one pod.

### Control file

The Java agent captures only while `/tmp/.postman-insights/control` in its container is fresh, says `enabled=1` and has a version it knows; otherwise it is dormant.
The Insights agent writes that file into the container of every JVM in the pods it monitors and refreshes it every 10 s, so capture stops by itself when a pod stops being monitored or the Insights agent goes away.
Without `java` in `--https-libraries` (`--https-libraries=openssl`), the files say disabled, and agents already loaded go dormant at the next refresh.
Writing the file for a JVM of another user needs `SYS_PTRACE` (the agent writes through `/proc/<pid>/root`).

### Loading the agent into running JVMs (DaemonSet)

As a DaemonSet, the Insights agent loads the Java agent into running HotSpot JVMs of monitored pods through the HotSpot attach mechanism, so no workload changes.
It runs the separate `postman-insights-jvm-attach` helper (`cmd/postman-insights-jvm-attach`, protocol in `ebpf/jvm/attach`) as each JVM's own user and group, which needs `SETUID` and `SETGID`.

1. The helper probes the JVM: is an agent loaded already (attached earlier, or started with `-javaagent`)?
2. Only if not, the Insights agent copies the jar into the JVM's container, as `/tmp/.postman-insights/agent-<checksum>/postman-insights-java-agent.jar`, and the helper loads it.
3. Once a JVM in a container runs the agent, the copies other Insights agent versions left there are removed, except those that a process sharing that directory still has mapped or open (a JVM keeps the jar it loaded mapped for as long as it runs).

A loaded agent cannot be replaced, so a JVM runs the version it loaded until it restarts; when that is not the Insights agent's own version, the log names both and the `ebpf-stats` line counts the JVM in `jvms_agent_other_version`.
JVMs that disable attach (`-XX:+DisableAttachMechanism`, `-XX:-EnableDynamicAgentLoading`) and OpenJ9 JVMs are skipped with the reason logged; they can still start with `-javaagent`.
On JDK 21 and newer, the JVM prints four `WARNING: A Java agent has been loaded dynamically ...` lines to its stderr when the agent attaches; they are harmless.
As a sidecar (`apidump`), the Insights agent loads nothing; the JVMs need `-javaagent`.
What happens to each JVM (attached, already running, skipped or failed, with the reason) is logged once and counted in the pod's telemetry as `java_jvm_*` events.

### Connection addresses

The kernel gives every event of a Java connection its addresses and ports, keyed by the agent's connection id (the `java_conns` map), in one of two ways.

- **Blocking `SSLSocket`:** the Java agent has the socket, so it sends the socket's addresses in an ADDRESS frame before the connection's first data frame.
  These frames are marked `SOCKET`, and the kernel never ties them by the thread's reads, since a read can return plaintext an earlier read already decrypted.
- **`SSLEngine`:** the Java agent sees engines, not sockets.
  The captured servers and clients unwrap a connection's handshake on the thread that read it, so the connection's first RECV frame is tied to the socket that thread last read bytes from (`tcp_recvmsg`, by fexit, or by kprobe and kretprobe on kernels without BPF trampolines) within 50 ms.
  The Java agent sends an empty RECV frame at the first unwrap that consumed TLS bytes, so the tie exists before the first request or response.
  A connection is tied once: Tomcat unwraps later records on another worker thread than the one that read them, and the connection keeps its addresses.
  Clients that read on one thread and unwrap on another (the JDK's `HttpClient`) write on the thread that wrapped, so a wrap whose bytes are yet to be written leaves the connection waiting for that thread's next `tcp_sendmsg`, within 10 ms.

Known limits: a connection unwrapped on another thread than the one that read it stays without addresses, unless that thread read another TCP socket within 50 ms, which it is then tied to; likewise an untied connection whose wrap is followed, within 10 ms and with no other connection's wrap in between, by the thread's write of another socket.
The `ebpf-stats` line counts data frames without addresses (`java_conn_unbound`) and RECV frames of a tied connection on a thread whose last read was another socket's (`java_conn_handoffs`): mostly Tomcat's hand-offs between threads, so it shows how often a server unwraps on another thread, not how many ties are wrong.

## 5. Limits and sampling

| Layer | Where | Flag (default) |
|---|---|---|
| 1. Payload truncation | kernel | `--https-body-size-cap` (16384 bytes per read or write) |
| 2. Per-PID rate cap | kernel token bucket, refilled every second | `--https-rate-cap-per-sec` (0, off) |
| 5. CPU thermostat: halves the payload cap while the agent's own CPU is high, and raises it back when it falls | userspace (`ebpf/thermostat_linux.go`) | `--no-thermostat` (false: the thermostat runs) |

Layer 4 is the witness rate limit of the HTTP path (`trace/rate_limit.go`), which HTTPS capture goes through unchanged; layer 3, a reservoir per route, was planned and is not built.
The Java agents read the kernel's current payload cap from the control file, so they copy no more than the kernel keeps.

## 6. Permissions

| Requirement | Why |
|---|---|
| Linux 5.8 or newer (RHEL 8 and its rebuilds on 4.18 through Red Hat's eBPF backports) | CO-RE programs, BPF ring buffer |
| `BPF` and `PERFMON` (or `SYS_ADMIN` on older kernels) | load programs, attach uprobes and tracepoints |
| `hostPID` and the host's `/proc` at `/host/proc` | see the node's processes, with the PIDs the kernel reports |
| `/sys/kernel/debug` (read-only) and `/sys/fs/bpf` | tracepoint ids, BPF maps |
| the CRI socket (DaemonSet) | map containers to their network namespaces |
| `SYS_PTRACE` (Java) | write the control file of a JVM running as another user, read JVMs' `/proc/<pid>/maps` |
| `SETUID` and `SETGID` (Java, DaemonSet) | run the attach helper as each JVM's user and group |

Without `SYS_PTRACE` the agent captures OpenSSL only; without `SETUID` and `SETGID`, a DaemonSet still captures JVMs started with `-javaagent`.
`kube inject`, `kube helm-fragment` and `kube tf-fragment` with `--enable-https-capture` generate the sidecar container with its mounts and `BPF`, `PERFMON` and, with `java`, `SYS_PTRACE` (`SidecarOpts` in `cmd/internal/kube/util.go`).
They do not change the pod spec: add `hostPID: true` and the hostPath volumes the mounts name (`sys-kernel-debug`, `sys-fs-bpf`, `host-proc`; `HTTPSCaptureVolumes` in the same file) yourself, as the Helm and Terraform fragments' comments say.
The programs only observe: they never change syscalls or packets, and the kernel verifier checks them before they load.

## 7. Privacy

HTTPS capture lets the agent see east-west traffic between services, which tends to carry service tokens and internal payloads that never crossed the edge as HTTP.
Captured messages go through the same witness and redaction path as HTTP capture: `Authorization` values are obfuscated, and `data_masks` redacts its sensitive keys and value patterns (`data_masks/redaction_config.yaml`) before anything leaves the host.
Payloads are capped per read and write (section 5), and plaintext stays on the node until redacted: the BPF ring buffer is readable only by the agent that loaded the programs.
There is no headers-only mode and no dry run yet: with HTTPS capture on, payloads up to the cap are captured.

## 8. Prior art

The libssl path follows OpenTelemetry eBPF Instrumentation (OBI, Apache-2.0, formerly Grafana Beyla): `ebpf/programs/libssl.bpf.c` mirrors the design of OBI's `bpf/generictracer/libssl.c`.
OBI hands Java plaintext to the kernel through `ioctl` with a magic command; this agent uses a positional write to `/dev/null` instead, and gets Java connections' addresses from the kernel.
The namespace bridge (containers to network namespaces through the CRI) is the pattern OBI, Datadog's system-probe and Falco use, because cgroup paths read across cgroup namespaces do not name the pod.
