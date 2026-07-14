# Releasing & Deploying the eBPF-enabled Insights Agent — Change Plan

Status: decisions locked (see §9). Owner: Shrey.
Scope: every change across the three repos needed to build, release, and deploy the agent now that it supports HTTPS capture via eBPF (in addition to the existing classic-BPF HTTP capture). Java TLS capture and its mutating-webhook deployment story are explicitly **out of scope for this release** (deferred to a later phase — see §9.5).

Repos referenced:
- `postman-insights-agent` — the open-source agent source.
- `observability-superstar-service` (a.k.a. superstar) — the backend monorepo; `cli-postman/` is where the *released* binary/image is actually built.
- `insights-agent-pkg-manager` — the release orchestrator + packaging/install tooling.

---

## 1. TL;DR — the decisions in this plan

All decisions below are **locked** (confirmed by the team — see §9 for the full record).

1. **Build strategy: one eBPF-enabled Linux build, rolled out RC-first.** ✅ We add eBPF to the single existing Linux build rather than maintaining two. This is safe for existing users because eBPF only does anything when the operator passes `--enable-https-capture` at runtime; with the flag off, behaviour is identical to today, even on old kernels. To protect the currently-working release, we roll the new build out through the `preview`/release-candidate tag first and only promote it to `latest` after validation. (Rejected alternative, kept as a documented safety valve: a separate eBPF image variant — §8.)
2. **`vmlinux.h`: commit a pre-generated copy per architecture** (amd64 + arm64) into the agent repo, **generated from a recent stable Ubuntu LTS kernel's BTF and refreshed at each release.** ✅ This is the smallest change that makes the eBPF build work on the existing macOS release machines; CO-RE handles adapting to customer kernels. (Concept explained in §3.1.)
3. **DaemonSet: the agent captures HTTPS in-process; remove the `ecapture` sidecar.** ✅ In-agent `--enable-https-capture` has reached parity with the sidecar, so the sidecar is deleted and its privileges move onto the agent container. Matches the design doc's "DaemonSet only, no sidecars." (Concept explained in §3.3.)
4. **deb/systemd and Beanstalk: HTTPS capture is opt-in.** ✅ Default behaviour stays HTTP-only; operators enable HTTPS explicitly (via `EXTRA_APIDUMP_ARGS` / an env toggle). No behaviour change for existing installs.
5. **Kernel floor: Linux 5.8+** for HTTPS capture (RHEL 8 / 4.18 via Red Hat's backports). This is a support-matrix and docs change, not a code change.
6. **macOS / Homebrew: unchanged.** eBPF is Linux-only; the Mac binary keeps working for HTTP capture and simply cannot do HTTPS-via-eBPF.
7. **Java TLS: out of scope this release.** ✅ Ship OpenSSL/Node/Go HTTPS capture now; defer `--enable-java-tls` and the mutating-webhook / JVM-injection deployment work to a later phase.

---

## 2. How the build & release works today (quick recap)

- The version number lives in one file: `observability-superstar-service/cli-postman/CURRENT_VERSION`.
- The **released Linux artifacts all come from one Docker build**: `make -C cli-postman cli-docker-release`, which uses `cli-postman/Dockerfile.cli.native`.
  - The **container image** pushed to public ECR is this image.
  - The **Linux static binary** put on S3 (and later into the Debian package and GitHub release) is *extracted from this same image* (see `insights-agent-pkg-manager/release/helpers/s3/release-insights-agent.sh`).
- The **macOS binary** comes from `make -C cli-postman native-bin` (not static; no eBPF).
- The whole release is driven by hand from macOS EC2 build machines: `insights-agent-pkg-manager/release/run.sh` → `helpers/run-amd64.sh` (and a parallel `run-arm64.sh` on a second machine).

The problem: `cli-postman/Dockerfile.cli.native` builds a **plain** binary. It has no eBPF toolchain (clang/llvm/bpftool), does not run the eBPF code generation step, has no `vmlinux.h`, and does not pass the `insights_bpf` build tag. So the released agent currently cannot do eBPF HTTPS capture even though the source code supports it.

---

## 3. Three concepts you'll need (plain language)

### 3.1 What `vmlinux.h` is and why it's the main blocker

eBPF programs are tiny programs that run *inside the Linux kernel*. To compile them, the compiler needs a description of the exact layout of the kernel's internal data structures. That description is a generated header file called `vmlinux.h`.

- It is normally produced from a running Linux machine by reading `/sys/kernel/btf/vmlinux` (BTF = "BPF Type Format", the kernel's built-in description of itself).
- Modern eBPF uses a technique called **CO-RE** ("Compile Once, Run Everywhere"): as long as you compile against *a* reasonably recent `vmlinux.h`, the program automatically adapts to whatever kernel it actually runs on later. So we don't need one `vmlinux.h` per customer kernel — one recent one per CPU architecture is enough.
- **Why it's a blocker for us:** our release machines are **macOS**, and a Mac has no Linux kernel and therefore no `/sys/kernel/btf/vmlinux` to generate this file from. And the file differs between the two CPU architectures we ship (amd64 and arm64), which are built on two different Macs.

The agent repo already git-ignores this file (`ebpf/programs/.gitignore` contains `vmlinux.h`), which is why it isn't in the build today.

**Decision:** generate `vmlinux.h` once on a Linux box for each architecture from **a recent stable Ubuntu LTS kernel's BTF**, and **commit both into the repo** (e.g. `ebpf/programs/vmlinux_amd64.h` and `ebpf/programs/vmlinux_arm64.h`, with the build selecting the right one). Then the Mac-based Docker build just copies the correct file in. This is exactly the pattern the existing `build-scripts/Dockerfile.ebpf` anticipates in its comments. It's the least disruptive option; the alternative (moving eBPF compilation onto Linux CI runners) is cleaner long-term but changes where release artifacts are built, which is a much bigger lift. **Refresh cadence:** regenerate the committed headers at each release from the current stable LTS kernel — CO-RE means we don't need to track customer kernel versions, so a recent LTS baseline is sufficient.

### 3.2 What "build tags" mean here

The agent's eBPF code is guarded by a Go build tag called `insights_bpf`. If you build **without** that tag, all the eBPF code is replaced by do-nothing stub files (that's how the Mac build and old CI keep compiling without clang). If you build **with** `-tags insights_bpf`, the real eBPF paths are compiled in — and that build now *requires* clang, `bpf2go`, and `vmlinux.h` to be present. So "adding eBPF to the release" concretely means "make the release Docker build use `-tags insights_bpf`, and give it the tools that tag now requires."

### 3.3 What the `ecapture` sidecar is and why it goes away

In the current Kubernetes DaemonSet (`insights-agent-pkg-manager/install_scripts/postman-insights-agent-daemonset.yaml`), HTTPS capture is done by a **second container running alongside the agent** called `ecapture-sidecar` (eCapture is an open-source eBPF TLS-capture tool). It decrypts TLS traffic and writes it to a file that the agent then reads.

Two problems with that today: it's a stopgap, and its image is set to `imagePullPolicy: Never` with a local dev tag (`postman-insights-agent-ecapture:debug-v2`) — meaning that manifest only ever worked on a machine where someone had built that image by hand. It was never a real, published, releasable thing.

The whole point of the new eBPF work is that **the agent now does this capture itself, in its own process**, via `--enable-https-capture`. So the sidecar can be deleted, and the eBPF privileges move onto the agent container. The design doc explicitly locks this in ("DaemonSet only, no sidecars"). The one thing to confirm with the team is that in-agent capture has reached parity with what the sidecar was doing (see §9).

---

## 4. Changes repo by repo

### 4.A `postman-insights-agent` (the agent source)

1. **Commit `vmlinux.h` per architecture.**
   - Remove `vmlinux.h` from `ebpf/programs/.gitignore` (or add explicit exceptions for the committed per-arch files).
   - Add `ebpf/programs/vmlinux_amd64.h` and `ebpf/programs/vmlinux_arm64.h`, generated from a recent stable Ubuntu LTS kernel's BTF on a Linux host of each arch. Regenerate these at each release (see §3.1).
   - Decide the selection mechanism: simplest is a tiny build step that copies the right file to `ebpf/programs/vmlinux.h` based on `TARGETARCH` before `go generate`.
   - *Why:* without this, the Mac release build cannot compile the eBPF programs.

2. **Confirm the code-generation + build recipe is what the release will use.** The canonical eBPF build steps already exist and are proven in `build-scripts/Dockerfile.ebpf-bin`:
   - `go install github.com/cilium/ebpf/cmd/bpf2go@v0.18.0`
   - `cd ebpf/loader && go generate -tags insights_bpf ./...`
   - `go build -tags "insights_bpf,osusergo,netgo" -ldflags "-linkmode external -extldflags '-static'" ...`
   - No source change needed here beyond making sure these exact steps get mirrored into the superstar release Dockerfile (§4.B). Note the generated `*_bpfel.go` files remain git-ignored and must be regenerated in every build environment.

3. **Keep the non-Linux/stub path intact.** No change — this is what lets the macOS build keep compiling. Just verify `make native-bin` (macOS) still builds cleanly after the `.gitignore`/`vmlinux.h` changes.

4. **Docs / support matrix (from the design doc, §8).** Add or finalize the customer-facing docs the design doc promises: `docs/security-permissions.md` (capabilities, mounts, kernel floor), `docs/https-data-flow.md`, `docs/redaction-defaults.md`. State the **Linux 5.8+ floor** and the "HTTPS capture is Linux-only" limitation.

5. **README / flags.** Ensure `README.md` documents the new user-visible flags (`--enable-https-capture`, `--enable-java-tls`, `--https-capture-mode`, rate/body caps) per the repo's own convention of updating the README when the interface changes.

### 4.B `observability-superstar-service` → `cli-postman/` (the real release build)

This is where most of the build work lives.

1. **Teach `cli-postman/Dockerfile.cli.native` to build eBPF.** Merge the eBPF setup from `postman-insights-agent/build-scripts/Dockerfile.ebpf-bin` into it, while keeping everything that makes it a *release* build (the `./cliv2` target that links the proprietary plugin, and the version/telemetry `-ldflags`). Concretely, in the `build` stage:
   - `apk add --no-cache clang llvm bpftool libbpf-dev linux-headers` (in addition to the existing `libpcap-dev gcc musl-dev`). Alpine is already used and is exactly why static linking + eBPF works cleanly (Debian's libpcap pulls in D-Bus and breaks static linking — noted in both Dockerfiles).
   - `go install github.com/cilium/ebpf/cmd/bpf2go@v0.18.0` and put it on `PATH`.
   - Copy in the correct `vmlinux.h` for `TARGETARCH`.
   - `cd ebpf/loader && go generate -tags insights_bpf ./...` before the build.
   - Add `insights_bpf` to the existing `-tags osusergo,netgo` so it becomes `-tags "insights_bpf,osusergo,netgo"`. Keep the existing `-ldflags` (version, git SHA, amplitude key) and add the static-link flags already present.
   - Keep the final `FROM alpine:3.22.0` runtime stage; add `libpcap` if the runtime needs it (the current release image copies a fully static binary, so confirm nothing new is dynamically linked after adding eBPF).

2. **`cli-postman/Makefile`.** The `cli-docker-release` / `cli-docker-ci` targets pass build args and don't need structural change, but:
   - Ensure the Docker build receives `TARGETARCH` (or an equivalent build-arg) so the right `vmlinux.h` is selected.
   - Consider a guard so a missing `vmlinux.h` fails loudly with a clear message rather than silently building a non-eBPF binary.
   - `native-bin` (macOS): **leave as-is** (no `insights_bpf`). This is intentional — macOS has no eBPF.

3. **Superstar CI.** If superstar's CI builds the CLI image for integration tests, that build will now need the eBPF toolchain too, or it should explicitly keep building the non-eBPF (stub) variant for tests. Decide which; at minimum make sure CI doesn't break when the Dockerfile changes.

4. **Version bump.** Because this is a new capability, bump `cli-postman/CURRENT_VERSION` as a **minor** release (e.g. `0.40.x` → `0.41.0`) when cutting it. The release script does this bump for you when you pass `minor`.

### 4.C `insights-agent-pkg-manager` (release + packaging + deploy)

1. **Release scripts — mostly unchanged, a few checks.** `release/helpers/ecr/release-insights-agent.sh` and `.../s3/release-insights-agent.sh` both just call `make -C cli-postman cli-docker-release` and then push/extract. Because we're keeping a **single** build, these scripts need **no structural change** — they'll automatically produce the eBPF-enabled artifacts once the Dockerfile changes. Recommended additions:
   - A post-build smoke check that the produced binary actually has eBPF compiled in (e.g. run `postman-insights-agent --help` and confirm `--enable-https-capture` is present, or a dedicated self-check), so a silent fallback to a non-eBPF build can't slip through a release.
   - Keep the existing `preview`-then-`latest` tagging in `run-amd64.sh` (`PIA_PUBLIC_ECR_MANIFEST` step) — this is the mechanism we lean on for a safe rollout (§7).

2. **DaemonSet manifest — the biggest deployment change.** Rewrite `install_scripts/postman-insights-agent-daemonset.yaml`:
   - **Remove** the `ecapture-sidecar` container and its now-unneeded bits (the `shared-tls-capture` emptyDir used only for sidecar IPC).
   - **Move eBPF privileges onto the agent container.** Per the design doc §8.1 and the agent's own generated fragments (`cmd/internal/kube/print_fragment.go`):
     - `spec.hostPID: true`
     - agent container `securityContext.capabilities.add: [NET_RAW, BPF, PERFMON]` (the design doc also lists `NET_ADMIN`; on older kernels the fallback is `[SYS_ADMIN, NET_ADMIN]`).
     - hostPath volume mounts: `/sys/kernel/debug`, `/sys/fs/bpf`, and `/host/proc` (read-only) — plus the existing containerd socket / netns mounts.
   - **Pass `--enable-https-capture`** in the agent's `kube run` args.
   - Cross-check against what `postman-insights-agent kube inject --enable-https-capture` / `kube run` already generate, so the static manifest and the code-generated fragments agree.

3. **Debian package — capabilities.** `deb_build/pkg/DEBIAN/postinst` currently grants only `cap_net_raw,cap_setgid`. For HTTPS capture on bare Linux/EC2, the binary needs BPF capabilities too. Add `cap_bpf` and `cap_perfmon` (kernel 5.8+) to the `setcap` line, with a graceful fallback for older kernels. **Decision: HTTPS capture is opt-in.** The systemd unit (`deb_build/pkg/usr/lib/systemd/system/postman-insights-agent.service`) keeps running `apidump` without `--enable-https-capture` by default; operators turn it on via `EXTRA_APIDUMP_ARGS="--enable-https-capture"` in `etc/default/postman-insights-agent`. This keeps existing installs' behaviour and privilege posture unchanged.

4. **`etc/default/postman-insights-agent`.** Add a documented, commented-out example showing how to turn on HTTPS capture via `EXTRA_APIDUMP_ARGS="--enable-https-capture"`, and note the kernel 5.8+ requirement.

5. **Install script (`install_scripts/install-postman-insights-agent.sh`).** It auto-detects OS/arch. No structural change required, but:
   - Add a note/warning that HTTPS capture requires Linux 5.8+ and is unavailable on macOS.
   - Confirm the direct-download static binary path (arm64 Debian, RHEL/yum, Alpine, "other Linux") still points at the newly eBPF-enabled zips — it does, since those are the same S3 artifacts.

6. **Beanstalk config (`install_scripts/postman-insights-agent-beanstalk.config`).** Uses `ec2 setup`. **Decision: opt-in.** Thread an env toggle (reusing the existing `POSTMAN_INSIGHTS_ADDITIONAL_FLAGS`, or a dedicated `POSTMAN_INSIGHTS_ENABLE_HTTPS_CAPTURE` like the existing repro-mode toggle) to append `--enable-https-capture` only when the operator sets it. Default stays HTTP-only.

7. **`deb_build/README.md` / `install_scripts/README.md`.** Update to reflect the new capabilities, kernel floor, and the removal of the ecapture sidecar workflow.

---

## 5. Runtime & deployment requirements (summary to document once)

- **Kernel:** Linux 5.8+ for HTTPS capture (RHEL/CentOS/Rocky/Alma 8 with 4.18 supported via Red Hat backports). HTTP-only capture keeps working on older kernels.
- **Capabilities:** `CAP_BPF` + `CAP_PERFMON` (5.8+), plus existing `CAP_NET_RAW`; `CAP_SYS_ADMIN` fallback on older kernels.
- **Kubernetes:** `hostPID: true`; hostPath mounts for `/sys/kernel/debug`, `/sys/fs/bpf`, `/proc`.
- **Not supported:** macOS eBPF capture; any platform without kernel BTF.

---

## 6. Testing & verification

- **Agent repo:** the kind-based e2e workloads already added (Node.js, .NET, Go HTTPS apps under `install_scripts/test-services/` and the agent's e2e tests) should run against the eBPF-enabled *release* image, not just a dev build.
- **Release pipeline:** add the "does this binary actually have eBPF?" smoke check noted in §4.C.1.
- **Backend canary:** the superstar canary (`test/agent-install-tests/check-insights-agent-version.sh`) verifies the published version matches `CURRENT_VERSION` across all five channels. It does **not** test eBPF. Consider adding a minimal "loads BPF programs on a 5.8+ node" canary, or at least confirm the existing canary still passes with the larger image.
- **Image size / build time:** the eBPF toolchain and generation step will grow build time and image size somewhat; sanity-check both.

---

## 7. Rollout sequence (how we avoid breaking the working release)

This directly addresses the "single build might make the current one un-work" concern.

1. Land the agent-repo changes (committed `vmlinux.h`, docs).
2. Update `cli-postman/Dockerfile.cli.native`; build locally on both an amd64 and an arm64 machine and confirm the binary runs and reports `--enable-https-capture`.
3. Cut a **release candidate** (`run.sh --rc 1 minor`). RCs push only the `preview` ECR tag and skip S3/APT/Homebrew/GitHub — so real users on `latest` are untouched while you validate.
4. Validate the RC image in a test cluster (HTTP capture unchanged; HTTPS capture works; old-kernel node still fine with the flag off).
5. Only then cut the real release, which promotes `latest`, publishes binaries, updates APT/Homebrew, and creates the GitHub release.
6. Keep the previous release's image/binaries available for fast rollback.

If at any point the team decides the combined build is too risky, fall back to §8.

---

## 8. Rejected alternative (kept as a safety valve) — separate eBPF variant

The team chose the single-build approach (§1.1). This section is retained only as a documented fallback if the combined build later proves too risky. If the team ever prefers not to touch the default build at all:
- Keep `cli-postman/Dockerfile.cli.native` exactly as-is (plain build).
- Add a second build (e.g. `Dockerfile.cli.native.ebpf` + a `cli-docker-release-ebpf` make target) producing eBPF artifacts under distinct names/tags: ECR `:<version>-ebpf` (and `:latest-ebpf`), and S3 zips like `..._linux_<arch>_ebpf.zip`.
- Add parallel steps in the release helpers to build/push/extract the variant.
- Point only the Kubernetes DaemonSet (the one place that needs HTTPS) at the `-ebpf` image; leave apt/Homebrew/EC2 on the plain build.

Trade-off: lower risk to the existing artifacts, but more artifacts, more release steps, and two things to keep in version-sync. My recommendation remains the single build with the RC-first rollout (§7), because the eBPF paths are inert unless explicitly enabled — but this variant is a clean safety valve.

---

## 9. Decisions (locked)

1. **ecapture parity → confirmed replaced.** In-agent `--enable-https-capture` has reached parity with the `ecapture-sidecar`. We delete the sidecar from the shipped DaemonSet and move its privileges onto the agent container (§4.C.2).
2. **HTTPS default → opt-in** for deb/systemd and Beanstalk. Default behaviour stays HTTP-only; operators enable HTTPS explicitly (§4.C.3, §4.C.6).
3. **`vmlinux.h` source → stable Ubuntu LTS kernel, refreshed per release.** Commit amd64/arm64 headers generated from a recent LTS kernel's BTF; regenerate each release. CO-RE handles customer-kernel differences (§3.1, §4.A.1).
4. **Build strategy → single eBPF-enabled build, RC-first rollout** (§1.1, §7). The separate-variant approach (§8) is rejected but retained as a documented safety valve.
5. **Java TLS → out of scope this release.** Ship OpenSSL/Node/Go HTTPS capture now; defer `--enable-java-tls` and the mutating-webhook / JVM-injection deployment story to a later phase. That phase will add: publishing/injecting the Postman Java agent JAR, the `kube webhook` MutatingWebhookConfiguration deployment, and the associated `charts/postman-insights-webhook/` release story — none of which are touched by this release.

---

## 10. Checklist (once decisions are locked)

- [ ] `postman-insights-agent`: commit `vmlinux_amd64.h` / `vmlinux_arm64.h`; adjust `.gitignore`; arch-select step; docs; README flags.
- [ ] `cli-postman/Dockerfile.cli.native`: add eBPF toolchain + `go generate` + `insights_bpf` tag; keep version/telemetry ldflags and `./cliv2`.
- [ ] `cli-postman/Makefile`: pass `TARGETARCH`; fail-loud guard; leave `native-bin` untouched.
- [ ] Bump `cli-postman/CURRENT_VERSION` (minor).
- [ ] `insights-agent-pkg-manager` DaemonSet: remove ecapture; add caps/hostPID/mounts; pass `--enable-https-capture`.
- [ ] `deb_build` postinst: add `cap_bpf,cap_perfmon`; document opt-in flag in `etc/default`.
- [ ] Install script + Beanstalk + READMEs: kernel-floor notes, opt-in wiring.
- [ ] Release helpers: eBPF smoke check; confirm ECR/S3 steps unchanged.
- [ ] Tests: e2e against release image; canary still green; consider eBPF canary.
- [ ] Rollout: RC via `preview` → validate → promote `latest`.
