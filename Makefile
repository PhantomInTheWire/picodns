.PHONY: test test-e2e test-e2e-network test-race fmt build clean lint run run-recursive

test:
	go test ./...

test-e2e:
	go test ./tests/e2e

test-e2e-network:
	E2E_REAL_NETWORK=1 go test ./tests/e2e/... -v -timeout 120s

test-race:
	go test -race ./...

fmt:
	go fmt ./...

lint:
	go vet ./...

build:
	mkdir -p bin
	go build -o bin/dnsd ./cmd/dnsd

clean:
	rm -rf bin

run: build
	./bin/dnsd -listen :1053 -upstreams 1.1.1.1:53,8.8.8.8:53

run-recursive: build
	./bin/dnsd -recursive -listen :1053
