package config

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sylr/op-broker/internal/policy"
	"github.com/sylr/op-broker/internal/ref"
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

const multi = `
op:
  accounts:
    work: ABCDEFGHIJKLMNOPQRSTUVWXYZ
    personal: ZYXWVUTSRQPONMLKJIHGFEDCBA
  default_account: work
rules:
  - principals: ["user:sylvain@formance.com"]
    read: ["op://Private/**"]
  - principals: ["user:sylvain@formance.com"]
    accounts: [personal]
    read: ["op://Private/**"]
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
	// op.account is the single account, under the alias LegacyAccount.
	if !maps.Equal(cfg.Op.Accounts, map[string]string{LegacyAccount: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}) || cfg.Op.DefaultAccount != LegacyAccount {
		t.Errorf("legacy account = %v, default %q", cfg.Op.Accounts, cfg.Op.DefaultAccount)
	}
}

func TestParseAccounts(t *testing.T) {
	cfg, pol, err := Parse([]byte(multi))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Op.Accounts) != 2 || cfg.Op.DefaultAccount != "work" {
		t.Errorf("accounts = %v, default %q", cfg.Op.Accounts, cfg.Op.DefaultAccount)
	}
	r, err := ref.Parse("op://Private/a/b")
	if err != nil {
		t.Fatal(err)
	}
	id := policy.Identity{LoginName: "sylvain@formance.com"}
	if !pol.AllowField(id, "work", r) || !pol.AllowField(id, "personal", r) {
		t.Error("rules not compiled against the configured accounts")
	}

	// With one account, default_account is implied.
	cfg, _, err = Parse([]byte("op:\n  accounts:\n    solo: ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Op.DefaultAccount != "solo" {
		t.Errorf("implied default = %q", cfg.Op.DefaultAccount)
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
		"second document":           valid + "\n---\nrules: []\n",
		"malformed second document": valid + "\n---\n: [\n",
		"no account":                "op:\n  timeout: 20s\n",
		"account and accounts":      strings.Replace(multi, "  default_account: work", "  default_account: work\n  account: ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1),
		"account and default":       strings.Replace(valid, "  timeout: 20s", "  timeout: 20s\n  default_account: default", 1),
		"missing default account":   strings.Replace(multi, "  default_account: work\n", "", 1),
		"unknown default account":   strings.Replace(multi, "default_account: work", "default_account: home", 1),
		"alias with uppercase":      strings.Replace(multi, "    work:", "    Work:", 1),
		"alias with dot":            strings.Replace(multi, "    work:", "    w.rk:", 1),
		"alias too long":            strings.Replace(multi, "    work:", "    "+strings.Repeat("a", 33)+":", 1),
		"alias not a UUID":          strings.Replace(multi, "ZYXWVUTSRQPONMLKJIHGFEDCBA", "my.1password.com", 1),
		"duplicate UUID":            strings.Replace(multi, "ZYXWVUTSRQPONMLKJIHGFEDCBA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1),
		"rule with unknown account": strings.Replace(multi, "accounts: [personal]", "accounts: [home]", 1),
		"rule with legacy alias":    strings.Replace(multi, "accounts: [personal]", "accounts: [default]", 1),
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

	other := t.TempDir()
	if err := os.Symlink(path, filepath.Join(other, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(filepath.Join(other, "config.yaml")); err == nil {
		t.Error("Load followed a symlink to a file outside the directory")
	}

	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, _, err := Load(path); err == nil {
		t.Error("Load accepted a config in a world-writable directory")
	}
}
