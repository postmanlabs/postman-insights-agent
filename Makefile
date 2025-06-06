.PHONY: clean build test mock

export GO111MODULE = on

build: clean
	go build -o bin/postman-insights-agent .

docker-build:
	docker build --target bin --output type=local,dest=bin,include=/postman-insights-agent --provenance false -f build-scripts/Dockerfile . 

clean:
	go clean

mock:
	go generate ./rest

test: mock
	go test ./...
