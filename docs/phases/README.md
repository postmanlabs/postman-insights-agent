# Phased delivery — session briefs for HTTPS capture

This directory contains **execution briefs** for the multi-session delivery of HTTPS traffic capture via eBPF.

Each phase brief is designed to be **self-contained**: a fresh engineer or AI coding agent should be able to read the brief plus [`../https-capture-design.md`](../https-capture-design.md) and execute the phase end-to-end, without needing to read prior chat history.

## How to start a session

Open a fresh agent session and use a prompt like:

> Read `docs/phases/phase-N.md` and execute it end-to-end. Branch from
> `feat/https-capture-ebpf` into a sub-branch `feat/https-capture-ebpf-phaseN`.
> When you hit the exit criteria, open a PR back into `feat/https-capture-ebpf`.

That's the entire prompt. The brief is the contract.

## Phases

| # | Brief | Goal | Requires Linux? | Effort |
|---|---|---|:---:|---|
| 1 | [`phase-1.md`](phase-1.md) | Spike — decrypted HTTPS bytes reach `trace.Collector` | ✅ | 2 weeks |
| 2 | [`phase-2.md`](phase-2.md) | Production integration into `apidump` command | ✅ | 3 weeks |
| 3 | [`phase-3.md`](phase-3.md) | Go support via OBI's DWARF inspector | ✅ | 4 weeks |
| 4 | [`phase-4.md`](phase-4.md) | Privacy & redaction hardening (the 8 gaps) | ⚠️ partial | 2 weeks |
| 5 | [`phase-5.md`](phase-5.md) | Java agent + mutating webhook | ✅ | 6 weeks |

## Recommended ordering

1. **Phase 1 + Phase 2 in one combined session.** They are tightly coupled — Phase 2 wires the adapter that Phase 1 produces bytes for. Splitting them risks Phase 2 guessing at byte formats Phase 1 hasn't proven yet.
2. **Phase 4 before Phase 3.** Finance/enterprise customers care more about "you can prove redaction works" than "you support Go services". Phase 4 unblocks the security review path.
3. **Phase 3** when you have Go customers waiting.
4. **Phase 5** last — it's a different problem (Gradle build, ByteBuddy, K8s admission webhooks) and benefits from a mature Phase 2 to integrate against.

## Conventions used in every brief

Every brief is structured the same way:

1. **Status banner** — what state the branch should be in before starting.
2. **Goal** — single sentence describing the exit state.
3. **Prerequisites** — exact commits/files to read first.
4. **Exit criteria** — testable, binary pass/fail conditions.
5. **Tasks** — file-level granularity, in dependency order.
6. **Common failure modes** — gotchas that have bitten OBI/Datadog/us before.
7. **Validation** — exact commands to run before claiming done.
8. **Handoff** — what to update for the next phase to pick up cleanly.

## Reference repositories

Cloned to `/Users/swamy.hiremath@postman.com/playground/insights-ebpf-research/` (outside the agent repo):

- `obi/` — OpenTelemetry eBPF Instrumentation. **Primary reference.** Apache-2.0.
- `datadog-agent/` — Datadog system-probe. Reference for Go DWARF inspector.
- `pixie/` — CNCF/Pixie. Older BCC style; reference for protocol coverage breadth.
- `ecapture/` — TLS-plaintext capture. Reference for static-binary symbol resolution.

Each phase brief lists the specific files within these repos to study before writing code.
