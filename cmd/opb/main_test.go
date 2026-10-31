package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sylr/op-broker/internal/api"
	"github.com/sylr/op-broker/internal/client"
)

func TestFailExitCodes(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{&client.Error{Code: api.CodeDenied}, exitDenied},
		{fmt.Errorf("wrapped: %w", &client.Error{Code: api.CodeDenied}), exitDenied},
		{&client.Error{Code: api.CodeOpLocked}, exitLocked},
		{&client.Error{Code: api.CodeTimeout}, exitLocked},
		{&client.Error{Code: api.CodeNotFound}, exitError},
		{&client.Error{Code: api.CodeOpFailed}, exitError},
		{&client.Error{Code: api.CodeBadRequest}, exitError},
		{errors.New("connection refused"), exitError},
		{&usageError{&cobra.Command{Use: "x"}, errors.New("bad")}, exitError},
		{nil, exitOK},
	}
	for _, tt := range tests {
		if got := fail(tt.err); got != tt.want {
			t.Errorf("fail(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	tests := map[string]string{
		"":               "''",
		"plain":          "'plain'",
		"it's":           `'it'\''s'`,
		"a\nb $X `y` \\": "'a\nb $X `y` \\'",
	}
	for in, want := range tests {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSettings(t *testing.T) {
	cfg, err := client.ParseConfig([]byte(`
current_context: home
contexts:
  home:
    server: http://home
    broker: user:me@example.com
  dev:
    server: http://localhost:8080
    allow_non_tailnet: true
  work:
    server: http://work
    broker: tag:op-broker
`))
	if err != nil {
		t.Fatal(err)
	}
	type flags struct {
		context, server, broker string
		allowNonTailnet         *bool
	}
	yes, no := true, false
	tests := []struct {
		name    string
		flags   flags
		env     map[string]string
		pin     string
		want    settings
		wantErr bool
	}{
		{name: "current context", want: settings{"home", "http://home", "user:me@example.com", false}},
		{name: "OPB_CONTEXT", env: map[string]string{"OPB_CONTEXT": "work"}, want: settings{"work", "http://work", "tag:op-broker", false}},
		{name: "--context over OPB_CONTEXT", flags: flags{context: "work"}, env: map[string]string{"OPB_CONTEXT": "home"}, want: settings{"work", "http://work", "tag:op-broker", false}},
		{name: "broker override keeps context server", env: map[string]string{"OPB_BROKER": "node:n1"}, want: settings{"home", "http://home", "node:n1", false}},
		{name: "--broker empty clears OPB_BROKER", flags: flags{broker: "-"}, env: map[string]string{"OPB_BROKER": "node:n1"}, want: settings{"home", "http://home", "", false}},
		{name: "server override drops context broker", env: map[string]string{"OPB_SERVER": "http://env"}, want: settings{"home", "http://env", "", false}},
		{name: "--server over OPB_SERVER", flags: flags{server: "http://flag"}, env: map[string]string{"OPB_SERVER": "http://env"}, want: settings{"home", "http://flag", "", false}},
		// An insecure context must not disable verification of another server.
		{name: "server override drops context allow_non_tailnet", flags: flags{context: "dev", server: "http://prod.example.ts.net"}, want: settings{"dev", "http://prod.example.ts.net", "", false}},
		{name: "insecure context", flags: flags{context: "dev"}, want: settings{"dev", "http://localhost:8080", "", true}},
		{name: "--allow-non-tailnet=false wins", flags: flags{context: "dev", allowNonTailnet: &no}, env: map[string]string{"OPB_ALLOW_NON_TAILNET": "1"}, want: settings{"dev", "http://localhost:8080", "", false}},
		{name: "OPB_ALLOW_NON_TAILNET", env: map[string]string{"OPB_ALLOW_NON_TAILNET": "1"}, want: settings{"home", "http://home", "user:me@example.com", true}},
		{name: "OPB_ALLOW_NON_TAILNET=0 overrides context", flags: flags{context: "dev"}, env: map[string]string{"OPB_ALLOW_NON_TAILNET": "0"}, want: settings{"dev", "http://localhost:8080", "", false}},
		{name: "invalid OPB_ALLOW_NON_TAILNET", env: map[string]string{"OPB_ALLOW_NON_TAILNET": "yes"}, wantErr: true},
		// A pinned bundle ignores leftover environment overrides.
		{name: "pin ignores env", pin: "work", env: map[string]string{"OPB_CONTEXT": "dev", "OPB_SERVER": "http://localhost:9999", "OPB_BROKER": "node:n1", "OPB_ALLOW_NON_TAILNET": "1"}, want: settings{"work", "http://work", "tag:op-broker", false}},
		{name: "pin with same --context", pin: "work", flags: flags{context: "work"}, want: settings{"work", "http://work", "tag:op-broker", false}},
		{name: "pin with other --context", pin: "work", flags: flags{context: "home"}, wantErr: true},
		{name: "pin with --server", pin: "work", flags: flags{server: "http://x"}, wantErr: true},
		{name: "pin with --broker", pin: "work", flags: flags{broker: "node:n1"}, wantErr: true},
		{name: "pin with --allow-non-tailnet", pin: "work", flags: flags{allowNonTailnet: &yes}, wantErr: true},
		{name: "unknown context", flags: flags{context: "nope"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &globals{cfg: cfg, getenv: func(k string) string { return tt.env[k] }}
			pf := newRootCmd(g).PersistentFlags()
			set := func(name, value string) {
				if err := pf.Set(name, value); err != nil {
					t.Fatal(err)
				}
			}
			if tt.flags.context != "" {
				set("context", tt.flags.context)
			}
			if tt.flags.server != "" {
				set("server", tt.flags.server)
			}
			if tt.flags.broker == "-" {
				set("broker", "")
			} else if tt.flags.broker != "" {
				set("broker", tt.flags.broker)
			}
			if tt.flags.allowNonTailnet != nil {
				set("allow-non-tailnet", strconv.FormatBool(*tt.flags.allowNonTailnet))
			}
			got, err := g.settings(tt.pin)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("settings(%q) = %+v, %v; want %+v, error %v", tt.pin, got, err, tt.want, tt.wantErr)
			}
		})
	}

	g := &globals{cfg: &client.Config{}, getenv: func(string) string { return "" }}
	if got, err := g.settings(""); err != nil || got != (settings{server: client.DefaultServer}) {
		t.Fatalf("no config: %+v, %v", got, err)
	}
}

func TestLoadConfigPath(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"XDG_CONFIG_HOME": dir}
	t.Setenv("XDG_CONFIG_HOME", dir)
	g := &globals{getenv: func(k string) string { return env[k] }}
	if err := g.loadConfig(); err != nil {
		t.Fatalf("missing default config: %v", err)
	}
	env["OPB_CONFIG"] = filepath.Join(dir, "missing.yaml")
	g = &globals{getenv: func(k string) string { return env[k] }}
	if err := g.loadConfig(); err == nil {
		t.Fatal("missing OPB_CONFIG accepted")
	}
}
