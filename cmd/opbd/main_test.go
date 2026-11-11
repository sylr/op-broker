package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sylr/op-broker/internal/config"
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

func TestReloadPolicy(t *testing.T) {
	const doc = `
op:
  accounts:
    work: ABCDEFGHIJKLMNOPQRSTUVWXYZ
    personal: ZYXWVUTSRQPONMLKJIHGFEDCBA
  default_account: work
rules:
  - principals: ["user:sylvain@formance.com"]
    accounts: [personal]
    read: ["op://Private/**"]
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(doc)
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	running := cfg.Op

	if _, err := reloadPolicy(path, running); err != nil {
		t.Fatalf("unchanged accounts: %v", err)
	}
	for name, changed := range map[string]string{
		"alias removed": strings.Replace(doc, "    personal: ZYXWVUTSRQPONMLKJIHGFEDCBA\n", "", 1),
		"alias renamed": strings.ReplaceAll(doc, "personal", "home"),
		"uuid changed":  strings.Replace(doc, "ZYXWVUTSRQPONMLKJIHGFEDCBA", "ZZZZZZZZZZZZZZZZZZZZZZZZZZ", 1),
		"alias added":   strings.Replace(doc, "  default_account:", "    extra: ZZZZZZZZZZZZZZZZZZZZZZZZZZ\n  default_account:", 1),
		"new default":   strings.Replace(doc, "default_account: work", "default_account: personal", 1),
	} {
		write(changed)
		if _, err := reloadPolicy(path, running); err == nil {
			t.Errorf("%s: reload accepted", name)
		}
	}
}

func TestReloadPolicyLegacy(t *testing.T) {
	const legacy = `
op:
  account: ABCDEFGHIJKLMNOPQRSTUVWXYZ
rules:
  - principals: ["user:sylvain@formance.com"]
    read: ["op://Private/**"]
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(legacy)
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	running := cfg.Op

	accepted := map[string]string{
		"unchanged": legacy,
		// The same account under its legacy alias.
		"explicit default": strings.Replace(legacy, "  account: ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			"  accounts:\n    default: ABCDEFGHIJKLMNOPQRSTUVWXYZ\n  default_account: default", 1),
		"implied default": strings.Replace(legacy, "  account: ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			"  accounts:\n    default: ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1),
	}
	for name, doc := range accepted {
		write(doc)
		if _, err := reloadPolicy(path, running); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Same UUID, but rules and clients name it differently.
	write(strings.Replace(legacy, "  account: ABCDEFGHIJKLMNOPQRSTUVWXYZ", "  accounts:\n    work: ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1))
	if _, err := reloadPolicy(path, running); err == nil {
		t.Error("renamed legacy account: reload accepted")
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
