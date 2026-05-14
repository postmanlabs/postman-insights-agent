# Phase 3 multi-Go-version test harness

See `docs/phases/phase-3-matrix.md` for the full procedure.

Quick start (assumes the `pia-bpf-dev` dev container is running and
older Go toolchains are installed via `golang.org/dl/go<ver>@latest`):

```bash
docker exec pia-bpf-dev bash /workspace/test/gomatrix/matrix_test.sh
```
