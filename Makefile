# Where `go install` puts binaries: GOBIN if set (including via `go env -w`),
# otherwise GOPATH/bin. The LaunchAgent must point at the same place.
INSTALL_DIR := $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)
AGENT := $(HOME)/Library/LaunchAgents/com.sylr.op-broker.plist
DOMAIN := gui/$(shell id -u)

.PHONY: build test install install-agent uninstall-agent

build:
	go build -o bin/opb ./cmd/opb
	go build -o bin/opbd ./cmd/opbd

test:
	go vet ./...
	go test -race ./...

install:
	GOBIN=$(INSTALL_DIR) go install ./cmd/opb ./cmd/opbd

install-agent: install
	sed -e 's|__HOME__|$(HOME)|g' -e 's|__OPBD__|$(INSTALL_DIR)/opbd|g' contrib/com.sylr.op-broker.plist > $(AGENT)
	-launchctl bootout $(DOMAIN)/com.sylr.op-broker 2>/dev/null
	launchctl bootstrap $(DOMAIN) $(AGENT)

uninstall-agent:
	-launchctl bootout $(DOMAIN)/com.sylr.op-broker
	rm -f $(AGENT)
