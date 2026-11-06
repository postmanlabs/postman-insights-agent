# Welcome! 👋

Postman Insights is designed to let you optimize your API performance in real
time. Using the drop-in Postman Insights Agent, you can bring your API
endpoints into Postman and assess your API traffic. Postman Insights allows you
to create collections based on the endpoints you're interested in the most, so
you can visually inspect your API productivity and fix any errors that may
occur.

The Postman Insights Agent runs on Kubernetes (as a DaemonSet or a sidecar),
Amazon Elastic Container Service (ECS) and Amazon EC2 or other Linux hosts.
Within 15 minutes of installing it in staging or production, you'll start to
see endpoints. The agent keeps these endpoints up to date based on new observed
traffic and its errors, latency, and volume.

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
1. Install [Go](https://golang.org/doc/install), at the version in `go.mod` (1.25).
2. Install `libpcap`
    - For Homebrew on mac: `brew install libpcap`
    - For Ubuntu/Debian: `apt-get install libpcap-dev`
3. `make`, which writes `bin/postman-insights-agent`

On Linux with `clang` and `bpftool` installed, `make` builds with HTTPS capture (eBPF); otherwise it builds without it.
See [`ebpf/README.md`](ebpf/README.md) for the eBPF build, including on macOS.

### How to test

1. Install [mockgen](https://github.com/golang/mock): `go install github.com/golang/mock/mockgen@v1.5.0`
2. `make test`

## HTTPS capture (eBPF)

Besides plaintext HTTP (libpcap), the agent can capture decrypted HTTPS traffic with eBPF.
It is opt-in and Linux-only.

- `--enable-https-capture` on `kube run` (DaemonSet) or `apidump` turns it on.
- It captures OpenSSL (`libssl`, shared or linked into Node.js) and, in preview, Java: as a DaemonSet the agent loads a Java agent into running JVMs; elsewhere the JVMs need `-javaagent`.
  `--https-libraries=openssl` turns Java capture off.
- Requirements: Linux 5.8 or newer (RHEL 8 and its rebuilds on 4.18 work through Red Hat's eBPF backports), `CAP_BPF` and `CAP_PERFMON` (or `CAP_SYS_ADMIN` on older kernels), `hostPID`, and access to `/sys/kernel/debug`, `/sys/fs/bpf` and the host's `/proc`.
- Java also needs `CAP_SYS_PTRACE`; without it the agent captures OpenSSL only.
  Loading the Java agent into running JVMs (DaemonSet) also needs `CAP_SETUID` and `CAP_SETGID`, to run the `postman-insights-jvm-attach` helper as each JVM's user; without them, JVMs started with `-javaagent` are still captured.

How it works, its limits and why each permission is needed: [`docs/https-capture-design.md`](docs/https-capture-design.md).
