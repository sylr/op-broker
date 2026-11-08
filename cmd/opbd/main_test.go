package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
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

func TestAgentSpec(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	spec, warning, err := agentSpec(home, "~/cfg.yaml", "/opt/homebrew/bin/opbd")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Config != filepath.Join(home, "cfg.yaml") {
		t.Errorf("config = %q", spec.Config)
	}
	if spec.Opbd != "/opt/homebrew/bin/opbd" {
		t.Errorf("opbd = %q", spec.Opbd)
	}
	if spec.Stderr != filepath.Join(home, "Library/Logs/op-broker.stderr.log") {
		t.Errorf("stderr = %q", spec.Stderr)
	}
	if warning != "" {
		t.Errorf("unexpected warning: %s", warning)
	}

	for _, p := range []string{
		"/opt/homebrew/Caskroom/op-broker/0.1.0/opbd",
		"/nix/store/0xsrhz0swjhf6syswdp1qpmj0qrymnad-op-broker-0.1.0/bin/opbd",
	} {
		if _, warning, err := agentSpec(home, "~/cfg.yaml", p); err != nil || warning == "" {
			t.Errorf("%s: warning = %q, err = %v; want a warning", p, warning, err)
		}
	}
}

func TestAgentMainUsage(t *testing.T) {
	var out bytes.Buffer
	if err := agentMain(nil, &out); err == nil {
		t.Error("no subcommand accepted")
	}
	if err := agentMain([]string{"start"}, &out); err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
		t.Errorf("err = %v", err)
	}
	if err := agentMain([]string{"install", "extra"}, &out); err == nil {
		t.Error("extra argument accepted")
	}
}

func TestCheckExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "opbd")
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkExecutable(exe); err != nil {
		t.Errorf("executable rejected: %v", err)
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{plain, dir, filepath.Join(dir, "missing")} {
		if err := checkExecutable(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}
