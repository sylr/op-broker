# Where `go install` puts binaries: GOBIN if set (including via `go env -w`),
# otherwise GOPATH/bin. The LaunchAgent must point at the same place.
INSTALL_DIR := $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)

.PHONY: build test install install-agent uninstall-agent

build:
	go build -o bin/opb ./cmd/opb
	go build -o bin/opbd ./cmd/opbd

test:
	go vet ./...
	go test -race ./...

install:
	GOBIN=$(INSTALL_DIR) go install ./cmd/opb ./cmd/opbd

# Does not build: run `make install install-agent` from source. Packaged
# installs run `opbd agent install` directly.
install-agent:
	$(INSTALL_DIR)/opbd agent install

uninstall-agent:
	$(INSTALL_DIR)/opbd agent uninstall
