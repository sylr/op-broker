package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestUserLogf(t *testing.T) {
	const url = "https://login.tailscale.com/a/0123456789"
	for _, toStderr := range []bool{true, false} {
		var log, stderr bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&log, nil))
		userLogf(logger, &stderr, toStderr)("To start this tsnet server, go to: %s", url)

		if !strings.Contains(log.String(), url) {
			t.Errorf("toStderr=%v: audit log lacks the URL: %s", toStderr, log.String())
		}
		if got := strings.Contains(stderr.String(), url); got != toStderr {
			t.Errorf("toStderr=%v: URL on stderr = %v: %q", toStderr, got, stderr.String())
		}
	}
}
