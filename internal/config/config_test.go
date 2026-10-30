package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const valid = `
hostname: op-broker
op:
  account: ABCDEFGHIJKLMNOPQRSTUVWXYZ
  timeout: 20s
request_timeout: 90s
rules:
  - principals: ["user:sylvain@formance.com"]
    read: ["op://Dev/**"]
`

func TestParseValid(t *testing.T) {
	cfg, pol, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if pol == nil {
		t.Fatal("nil policy")
	}
	home, _ := os.UserHomeDir()
	if want := filepath.Join(home, "Library/Application Support/op-broker/tsnet"); cfg.StateDir != want {
		t.Errorf("StateDir = %q, want %q", cfg.StateDir, want)
	}
	if cfg.Op.Timeout != 20*time.Second || cfg.RequestTimeout != 90*time.Second {
		t.Errorf("timeouts = %s, %s", cfg.Op.Timeout, cfg.RequestTimeout)
	}
	if cfg.Listen != ":80" || cfg.Op.Path != "/opt/homebrew/bin/op" {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string]string{
		"missing account":           strings.Replace(valid, "account: ABCDEFGHIJKLMNOPQRSTUVWXYZ", "account: \"\"", 1),
		"account shorthand":         strings.Replace(valid, "account: ABCDEFGHIJKLMNOPQRSTUVWXYZ", "account: formance", 1),
		"unknown key":               valid + "\nbogus: true\n",
		"relative op path":          strings.Replace(valid, "  timeout: 20s", "  timeout: 20s\n  path: op", 1),
		"bad rule":                  strings.Replace(valid, "op://Dev/**", "Dev/**", 1),
		"request timeout too short": strings.Replace(valid, "request_timeout: 90s", "request_timeout: 1s", 1),
		"request timeout too long":  strings.Replace(valid, "request_timeout: 90s", "request_timeout: 300s", 1),
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("Parse succeeded, want error")
			}
		})
	}
}

func TestLoadPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err != nil {
		t.Fatalf("Load 0600: %v", err)
	}

	for _, mode := range []os.FileMode{0o644, 0o640, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Load(path); err == nil {
			t.Errorf("Load accepted a config with mode %v", mode)
		}
	}
	os.Chmod(path, 0o600)

	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(link); err == nil {
		t.Error("Load accepted a symlinked config")
	}

	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, _, err := Load(path); err == nil {
		t.Error("Load accepted a config in a world-writable directory")
	}
}
