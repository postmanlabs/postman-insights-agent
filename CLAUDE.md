# CLAUDE.md

Guidance for Claude Code (and other AI coding agents) when working in this repository.

## Project overview

This is the **Postman Insights Agent** — an open-source Go CLI that captures HTTP traffic from network interfaces (via libpcap), parses/witnesses requests and responses, and ships them to the Postman Insights backend so users can see endpoints, errors, latency, and volume in Postman.

- **Language:** Go (see `go.mod` — `go 1.23.3`, toolchain `go1.24.6`).
- **Module:** `github.com/postmanlabs/postman-insights-agent`
- **Entry point:** `main.go` → `cmd.Execute()` (Cobra-based CLI).
- **Binary name:** `postman-insights-agent`
- **License:** See `LICENSE`.
- **Origin:** Forked from / successor to the Akita Software agent — many internal packages still reference `akita*` and `akitasoftware/*` libs.

Note: This open-source repo does **not** include type/format inference. That functionality only exists in the official distributed binary.

## Build, test, run

System prerequisites:
- Go 1.18+ (repo currently pins 1.23/1.24).
- `libpcap`
  - macOS: `brew install libpcap`
  - Debian/Ubuntu: `apt-get install libpcap-dev`
- `mockgen` for tests: `go install github.com/golang/mock/mockgen@v1.5.0`

Common commands (from `Makefile`):

| Command         | What it does |
| --------------- | ------------ |
| `make`          | `make build` — produces `bin/postman-insights-agent` |
| `make build`    | `go build -o bin/postman-insights-agent .` (runs `clean` first) |
| `make clean`    | `go clean` |
| `make mock`     | `go generate ./rest` (regenerates gomock mocks) |
| `make test`     | `make mock` then `go test ./...` |
| `make docker-build` | Build via `build-scripts/Dockerfile`, output binary to `bin/` |

CI (`.circleci/config.yml`) runs `make` and `gotestsum --junitfile ...` against all packages.

## Repository layout

Top-level CLI plumbing:
- `main.go` — trivial entry point.
- `cmd/` — Cobra command tree (`root.go`, `supervisor.go`).
- `cmd/internal/` — subcommand implementations:
  - `apidump/` — `apidump` command: the core traffic-capture command.
  - `ec2/` — `ec2 setup|remove`: install agent as a systemd service on EC2.
  - `ecs/` — `ecs add|remove|cf-fragment|task-def`: AWS ECS integration.
  - `kube/` — `kube inject|run|secret|helm-fragment|tf-fragment`: Kubernetes integration (DaemonSet, sidecar injection, manifests).
  - `legacy/` — legacy `specs` and other deprecated commands.
  - `ascii/`, `akiflag/`, `cmderr/`, `pluginloader/` — CLI utilities.

Core domain packages:
- `apidump/` — orchestrates a capture session: pcap → parse → trace → backend.
- `pcap/` — libpcap wrappers, packet/stream reassembly, replay.
- `learn/` — HTTP parsing (request/response → IR "witnesses"), JSON preprocessing, event-stream parsing, Luhn checks.
- `trace/` — collectors (`backend_collector`, `dummy_collector`), rate limiting, stats, filters, reporting buffer.
- `rest/` — HTTP clients for the Postman/Akita backend (`front_client`, `learn_client`, base client, auth, errors). Mocks are generated here via `go generate`.
- `daemon/` — long-running daemon HTTP server.
- `plugin/` — pluggable architecture (`interface.go`, `akita/` plugin).

Integrations and platform helpers:
- `integrations/cri_apis/` — Container Runtime Interface client (containerd/CRI-O).
- `integrations/kube_apis/` — Kubernetes API access.
- `integrations/nginx/` — nginx-related helpers.
- `integrations/tests/` — integration tests.
- `aws_utils/` — AWS SDK helpers.
- `tcp_conn_tracker/`, `tls_conn_tracker/` — connection tracking.
- `useragent/`, `location/`, `version/`, `setversion/`, `telemetry/`, `usage/`, `printer/`, `consts/`, `cfg/`, `env/`, `util/` — utilities.

Other:
- `data_masks/` — PII/sensitive data redaction.
- `apispec/` — API spec generation/handling.
- `architecture/architecture.go` — architecture metadata.
- `docs/discovery-mode.md` — important user-facing doc explaining **Discovery Mode** vs **Workspace Mode** onboarding (Kubernetes). Read this before changing onboarding/k8s flows.
- `deployment/`, `build-scripts/`, `ci/` — release & deployment scripts.

## CLI surface (high level)

Root: `postman-insights-agent` (see `cmd/root.go`). Notable subcommands:

- `apidump` — Capture requests/responses from network traffic (primary command).
- `ec2 setup` / `ec2 remove` — Install/uninstall as systemd service on EC2.
- `ecs add|remove|cf-fragment|task-def` — Manage agent on AWS ECS.
- `kube inject|run|secret|helm-fragment|tf-fragment` — Kubernetes integration. `kube run` is the DaemonSet entrypoint (Linux only).
- `specs` (legacy) — Manage API specs.
- `aki` — ASCII art easter egg.

Test-only / hidden flags live on the root command (`testOnlyUseHTTPSFlag`, `dogfoodFlag`, `debugFlag`, profiling flags, etc.) — see `cmd/root.go`.

## Conventions and gotchas

- **Cobra + Viper + pflag** are used throughout. New subcommands should follow the pattern in `cmd/internal/<name>/<name>.go` and be wired into `cmd/root.go`.
- **Mocks**: `rest/` uses gomock. Run `make mock` (or `go generate ./rest`) after changing interfaces in `rest/interface.go`. `make test` does this automatically.
- **libpcap is required at build time** on every platform — `pcap/get_pcap_handle_linux.go` is Linux-only; the generic file covers other OSes.
- **Linux-only features**: `kube run` (DaemonSet mode) and some pcap paths assume Linux. Be mindful when adding code under build-tagged files.
- **Akita lineage**: Many package names, struct names, and dependencies still say `akita`. Do **not** rename these casually — they cross module boundaries (`github.com/akitasoftware/akita-ir`, `akita-libs`, `go-utils`). When in doubt, leave the name alone.
- **Backend talk** goes through `rest/` clients. Avoid hitting external HTTP from other packages directly.
- **Telemetry** is in `telemetry/`; usage events in `usage/`. Keep new event names consistent with existing ones.
- **Discovery vs Workspace mode**: see `docs/discovery-mode.md`. New k8s onboarding work should support both and avoid resurrecting the legacy `--project` / `--collection` flags.
- **Code owners**: see `.github/CODEOWNERS` before opening PRs.
- **Versioning**: SemVer; bump via files under `version/` and `setversion/` as documented in `CONTRIBUTING.md`.

## Running locally

```bash
make                                  # builds bin/postman-insights-agent
./bin/postman-insights-agent --help   # explore commands
./bin/postman-insights-agent apidump --help
```

Capturing traffic typically requires root / `CAP_NET_RAW` (libpcap). Use `sudo` locally or run inside the provided container.

## When making changes

1. Prefer small, well-scoped edits. The codebase mixes legacy Akita code with newer Postman code — don't refactor broadly without reason.
2. If you touch anything in `rest/`, regenerate mocks (`make mock`) and run `make test`.
3. If you add a subcommand, add it under `cmd/internal/<name>/` and register it in `cmd/root.go`.
4. If you change onboarding/k8s behavior, update `docs/discovery-mode.md`.
5. Update `README.md` per `CONTRIBUTING.md` when changing user-visible interface (env vars, flags, ports).
6. Run `make test` before claiming work is done. CI is `make` + `make mock` + `gotestsum`.
