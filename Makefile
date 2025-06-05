.PHONY: clean build test generate-test-dependencies

export GO111MODULE = on

build: clean
	go build -o bin/postman-insights-agent .

docker-build:
	docker build --target bin --output type=local,dest=bin,include=/postman-insights-agent --provenance false -f build-scripts/Dockerfile . 

clean:
	go clean

generate-test-dependencies:
	go generate ./rest

test: generate-test-dependencies
	go test ./...
