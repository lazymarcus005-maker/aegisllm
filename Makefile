SHELL := /bin/sh

.PHONY: test build vet fuzz-smoke load-short e2e-conformance verify-release

GOFLAGS ?=

test:
	go test -p 1 ./...

build:
	go build ./...

vet:
	go vet ./...

fuzz-smoke:
	scripts/release/fuzz-smoke.sh

load-short:
	scripts/release/load-short.sh

e2e-conformance:
	scripts/release/conformance-docker.sh

verify-release:
	scripts/release/verify-release.sh
