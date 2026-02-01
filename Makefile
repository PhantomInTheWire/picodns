.PHONY: test test-e2e fmt

test:
	go test ./...

test-e2e:
	go test -tags=e2e ./tests/e2e

fmt:
	gofmt -w ./cmd ./internal ./tests
