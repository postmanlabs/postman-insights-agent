# Security & Permissions — eBPF HTTPS Capture

**Audience:** customer security / platform-engineering teams reviewing
the Postman Insights Agent before deployment.

This document is the exhaustive list of what the agent needs from the
host in order to perform eBPF HTTPS capture, and what it explicitly
does *not* do with those permissions.

---

## Linux capabilities (when running as a DaemonSet)

| Capability | Why we need it | Could we drop it? |
|---|---|---|
| **CAP_BPF** | Load BPF programs (`bpf(BPF_PROG_LOAD)`). Kernel 5.8+ split this off from CAP_SYS_ADMIN. | No — strictly required for eBPF. |
| **CAP_PERFMON** | Attach perf events (uprobes via `perf_event_open`). Kernel 5.8+ split this off too. | No — required for uprobes. |
| **CAP_NET_ADMIN** | Read namespace inode info via `/proc/<pid>/ns/cgroup` for the CRI+cgroup-ns namespace bridge. | Possibly — we're investigating whether read-only `/proc` mounts can supply this without the capability. |
| **CAP_SYS_PTRACE** | NOT required. We deliberately do not use ptrace. | — |
| **CAP_SYS_ADMIN** | NOT required. Older eBPF designs needed this; modern split (CAP_BPF + CAP_PERFMON) means we don't. | — |

The DaemonSet manifest in `test/kind/agent-daemonset.yaml` shows the
production-realistic capability set.

## Linux syscalls we hook

Read-only uprobes (kernel attaches a probe; userspace processes are
unaware):

| Symbol | Library / Runtime | Purpose |
|---|---|---|
| `SSL_read`, `SSL_read_ex` | `libssl.so.*` (OpenSSL, BoringSSL dynamic) | Capture decrypted ingress bytes. |
| `SSL_write`, `SSL_write_ex` | same | Capture plaintext egress bytes before encryption. |
| `SSL_set_fd` | same | Bind an `SSL*` pointer to a file descriptor so we can resolve the 4-tuple. |
| `SSL_free` | same | Invalidate the `(SSL*, fd)` binding on connection close. |
| `crypto/tls.(*Conn).Write` (entry) | Go runtime, Linux ELF | Capture decrypted egress from Go services. |
| `crypto/tls.(*Conn).Read` (entry + N RET probes) | Go runtime | Capture decrypted ingress; RET probing because Go uretprobes are unreliable. |

**Notes:**

- All probes are *read-only*. eBPF uprobes cannot modify the function's
  arguments, return value, control flow, or process state.
- No `sys_*` syscalls are hooked. Phase 5 adds a single `sys_ioctl`
  kprobe used by the Java agent's bridge — that's documented separately
  when it ships.
- We do NOT hook `connect`, `accept`, `send`, `recv`, or any other
  socket-level syscall. We only see what passes through the TLS
  library API we've explicitly probed.

## Filesystem paths the agent reads

| Path | Read frequency | What we look at |
|---|---|---|
| `/proc/<pid>/maps` | On new-PID discovery (~once per process) | Locate `libssl.so*` mappings to pick uprobe attach addresses. |
| `/proc/<pid>/exe` | On new-PID discovery | Read ELF symbol table to identify Go binaries and find `crypto/tls.(*Conn).Write/Read` offsets. |
| `/proc/<pid>/cgroup`, `/proc/<pid>/ns/cgroup` | On new-PID discovery | Read cgroup-namespace inode for the CRI+cgroup-ns Kubernetes-namespace bridge. |
| `/proc/<pid>/net/tcp`, `/proc/<pid>/net/tcp6` | On TCP-connection-resolution (cached) | Resolve `(fd → 4-tuple)`. Read in the *target* process's network namespace so connection-pooled servers' tuples are correct. |
| `/sys/kernel/btf/vmlinux` | At agent startup | Load kernel BTF for cilium/ebpf's `Collection.LoadAndAssign`. |
| `/sys/fs/bpf` | At agent startup | (optional) Pin maps for cross-process sharing. We currently do NOT pin maps — they're owned by the agent process and unlinked on exit. |
| `/var/log/postman-insights/` | Only in `--privacy-mode=dry-run` | Write redaction reports (no other use of this path). |

The agent never reads:
- `/proc/<pid>/mem` — we don't dump process memory.
- `/proc/<pid>/environ` — we don't read environment variables.
- `/proc/<pid>/cmdline` — we read only `comm` (process name) for telemetry.
- `~/.ssh/`, `/etc/shadow`, or any path containing credentials.

## Kubernetes RBAC

The DaemonSet ServiceAccount needs:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list", "watch", "get"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["list", "watch"]
```

That's it. We do not:
- read secrets,
- read configmaps,
- create/update/delete *any* resource,
- exec into pods,
- read pod logs.

The agent's interaction with the kube-apiserver is exclusively
*read-list-watch on pods + namespaces*, used to map cgroup namespaces to
Kubernetes namespaces for the `--target-namespaces` filter.

## Container Runtime Interface (CRI)

The agent mounts the CRI socket read-only:

```yaml
volumeMounts:
  - name: cri-socket
    mountPath: /var/run/containerd/containerd.sock
    readOnly: true
```

It calls only `ListContainers` and `ContainerStatus` (gRPC) — both
read-only. We do not Exec, Attach, RemoveContainer, or any other
mutation method.

## Network egress

| Destination | Port | Protocol | Why |
|---|---|---|---|
| `api.postman.com` | 443 | HTTPS (TLS 1.2+, cert-pinned) | Witness batches, dynamic config polling, telemetry. |

There is exactly **one outbound network destination**. The agent makes
no calls to third-party telemetry vendors, no GitHub fetches, no
package-manager calls at runtime.

You can verify this with `iptables -L` after attaching the agent —
egress to anything other than `api.postman.com:443` is a bug worth
reporting.

## Process isolation

The agent runs:
- As a single Go process (no helper scripts, no shelled-out commands
  during steady-state operation).
- Inside a container (when deployed as a DaemonSet) so kernel
  namespaces protect it from co-located workloads' filesystems.
- With `hostPID: true` and `hostNetwork: true` (DaemonSet only) so it
  can see other pods' PIDs and network namespaces. This is required for
  cross-namespace HTTPS capture and is the standard pattern for
  observability DaemonSets (Datadog Agent, OBI, Pixie all use it).
- Without `hostPath` mounts other than `/proc`, `/sys`, and the CRI
  socket.

## What the agent CANNOT do, by design

(Cross-referenced with `https-data-flow.md` for completeness.)

- Cannot **modify** any HTTPS traffic. eBPF uprobes are read-only.
- Cannot **block** any syscall. We don't use `kprobe` overrides.
- Cannot **decrypt** traffic from a TLS library we haven't probed.
  Java JSSE, statically-linked BoringSSL, and rustls are NOT covered as
  of the current release.
- Cannot **send data anywhere except `api.postman.com:443`**.
- Cannot **read application memory** outside the buffer passed to a
  probed function.
- Cannot **persist data to disk** except dry-run redaction reports.
- Cannot **execute arbitrary code** in the application process. eBPF
  programs run in the kernel, are verifier-checked at load time, and
  are confined to the BPF helper API.

## Verifying these claims yourself

```bash
# 1. Confirm capabilities.
kubectl exec -n postman-insights ds/postman-insights-agent -- \
  cat /proc/self/status | grep ^Cap

# 2. Confirm network egress.
kubectl exec -n postman-insights ds/postman-insights-agent -- \
  ss -tn state established
# Should show ONLY api.postman.com:443 connections.

# 3. Audit what eBPF programs are loaded.
kubectl exec -n postman-insights ds/postman-insights-agent -- \
  bpftool prog list | grep insights

# 4. Audit what uprobes are attached.
kubectl exec -n postman-insights ds/postman-insights-agent -- \
  cat /sys/kernel/debug/tracing/uprobe_events
```

## Related documents

- [`docs/https-data-flow.md`](https-data-flow.md) — end-to-end data
  flow with per-step visibility/encryption.
- [`docs/redaction-defaults.md`](redaction-defaults.md) — what's
  redacted by default.
- [`docs/https-capture-design.md`](https-capture-design.md) §2 (threat
  model) §10 (operational guardrails).
