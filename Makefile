.PHONY: clean build build-ebpf test mock dev-shell dev-build dev-down

export GO111MODULE = on

build: clean
	go build -o bin/postman-insights-agent .

# build-ebpf produces a Linux binary with the eBPF HTTPS-capture pipeline
# compiled in. It requires:
#   * clang >= 14, llvm-strip, bpftool, libbpf-dev installed locally
#   * vmlinux.h dumped from /sys/kernel/btf/vmlinux into ebpf/programs/
# Use `make dev-shell` on macOS to get a container with all of the above.
build-ebpf: clean
	cd ebpf/loader && go generate -tags insights_bpf ./...
	go build -tags insights_bpf -o bin/postman-insights-agent .

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
