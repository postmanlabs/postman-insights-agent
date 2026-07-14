# Welcome! 👋

Postman Insights is designed to let you optimize your API performance in real
time. Using the drop-in Postman Insights Agent, you can bring your API
endpoints into Postman and assess your API traffic. Postman Insights allows you
to create collections based on the endpoints you're interested in the most, so
you can visually inspect your API productivity and fix any errors that may
occur.

Postman is working toward the open launch of Postman Insights. Today, the alpha
release enables you to leverage the Postman Insights Agent on Amazon Elastic
Container Service (ECS) deployments. Within 15 minutes of installing the
Postman Insights Agent in staging or production, you'll start to see endpoints.
The Postman Insights Agent will keep these endpoints up to date based on new
observed traffic and its errors, latency, and volume.

We're excited for you to try out the new features and give us your feedback so
we can continue tailoring the product to your needs.

  [About this repo](#about-this-repo)
| [Running this repo](#running-this-repo)

## About this repo
This is the open-source repository for the community version of the Postman
Insights Agent, and is intended for use with Postman. This community version of
the Postman Insights Agent does not include functionality for inferring types
and data formats. This functionality is available only in the
`postman-insights-agent` binary that we distribute.

## Running this repo

### How to build
Running the following commands will generate the `postman-insights-agent`
binary:
1. Install [Go 1.18 or above](https://golang.org/doc/install).
2. Install `libpcap`
    - For Homebrew on mac: `brew install libpcap`
    - For Ubuntu/Debian: `apt-get install libpcap-dev`
3. `make`


### How to test

1. Install [gomock](https://github.com/golang/mock): `go get github.com/golang/mock/mockgen`
2. `make test`

## HTTPS capture (eBPF)

In addition to plaintext HTTP capture (classic BPF via libpcap), the agent can
capture decrypted HTTPS traffic using eBPF uprobes on TLS libraries. This is
**opt-in** and **Linux-only**.

- Enable it by passing `--enable-https-capture` to `apidump` (add
- Related flags: `--https-capture-mode`, and the HTTPS rate/body-size caps.
- **Requirements:** Linux kernel **5.8+** (RHEL/CentOS/Rocky/Alma 8 with 4.18 is
  supported via Red Hat's eBPF backports). Requires `CAP_BPF` + `CAP_PERFMON`
  (or `CAP_SYS_ADMIN` on older kernels) and access to `/sys/kernel/debug`,
  `/sys/fs/bpf`, and host `/proc`.
- **Not available on macOS** — the macOS build captures HTTP only; all eBPF
  paths compile to no-ops there.

Building with eBPF requires the `insights_bpf` build tag plus clang and
`bpf2go`, and a `vmlinux.h` generated from the build host's kernel BTF (produced
automatically at build time; requires a native per-arch Linux build). On Linux
with clang + bpftool installed, `make` auto-detects the toolchain and builds
with eBPF; otherwise it builds the plain binary. See `ebpf/programs/README.md`
for details.
