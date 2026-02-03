.PHONY: test test-e2e test-race fmt build clean lint

test:
	go test ./...

test-e2e:
	go test -tags=e2e ./tests/e2e

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
