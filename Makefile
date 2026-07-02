.PHONY: clean build test mock dev-shell dev-build dev-down

export GO111MODULE = on

# Detect whether the eBPF toolchain is available on this host.
# On Linux with clang + bpftool installed, the binary is built with the
# insights_bpf tag so HTTPS capture via eBPF is included.
# On macOS or Linux without the toolchain the plain binary is built — all
# eBPF paths compile to no-ops via their stub files, preserving the
# existing behaviour on non-Linux platforms.
UNAME_S := $(shell uname -s)
HAS_CLANG := $(shell command -v clang > /dev/null 2>&1 && echo yes)
HAS_BPFTOOL := $(shell command -v bpftool > /dev/null 2>&1 && echo yes)

ifeq ($(UNAME_S),Linux)
  ifeq ($(HAS_CLANG)$(HAS_BPFTOOL),yesyes)
    BUILD_TAGS := insights_bpf
  endif
endif

build: clean
ifeq ($(BUILD_TAGS),insights_bpf)
	@echo "==> eBPF toolchain detected — building with insights_bpf tag"
	cd ebpf/loader && go generate -tags insights_bpf ./...
else
	@echo "==> No eBPF toolchain (or non-Linux) — building without insights_bpf tag"
endif
	go build -tags "$(BUILD_TAGS)" -o bin/postman-insights-agent .

docker-build:
	docker build --target bin --output type=local,dest=bin,include=/postman-insights-agent --provenance false -f build-scripts/Dockerfile .

# --- Dev-container shortcuts for HTTPS-via-eBPF work on macOS. ---
dev-build:
	./build-scripts/dev-container.sh build

dev-shell:
	./build-scripts/dev-container.sh shell

dev-down:
	./build-scripts/dev-container.sh down

clean:
	go clean

mock:
	go generate ./rest

test: mock
	go test ./...
