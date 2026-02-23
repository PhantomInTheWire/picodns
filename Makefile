.PHONY: test test-e2e test-e2e-network test-race fmt build clean lint run run-recursive bench bench-million bench-realistic

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
	go build -o bin/picodns ./cmd/picodns

build-perf:
	mkdir -p bin
	go build -tags=perf -o bin/picodns ./cmd/picodns

clean:
	rm -rf bin

run: build
	./bin/picodns -listen :1053 -upstreams 1.1.1.1:53,8.8.8.8:53

run-recursive: build
	./bin/picodns -recursive -listen :1053

bench:
	./scripts/bench.py

bench-million:
	./scripts/bench_million.py

bench-realistic:
	./scripts/bench_realistic.py
