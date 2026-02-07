.PHONY: test test-e2e test-e2e-network test-race fmt build clean lint

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
