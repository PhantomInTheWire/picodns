.PHONY: test test-e2e fmt build

test:
	go test ./...

test-e2e:
	go test -tags=e2e ./tests/e2e

fmt:
	gofmt -w ./cmd ./internal ./tests

build:
	mkdir -p bin
	go build -o bin/dnsd ./cmd/dnsd
