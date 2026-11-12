package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sylr/op-broker/internal/api"
	"github.com/sylr/op-broker/internal/client"
)

const testConfig = `current_context: home
contexts:
  home:
    server: http://op-broker.example.ts.net
  work:
    server: http://op-broker.corp.ts.net
    broker: tag:op-broker
bundles:
  db:
    env:
    - name: PGPASSWORD
      ref: op://Dev/postgres/password
  aws:
    context: work
    env:
    - name: AWS_ACCESS_KEY_ID
      ref: op://Prod/aws/access key id
    - name: AWS_SECRET_ACCESS_KEY
      ref: op://Prod/aws/secret access key
  aws-ro:
    context: work
    env:
    - name: AWS_ACCESS_KEY_ID
      ref: op://Prod/aws-ro/access key id
  other:
    context: home
    env:
    - name: TOKEN
      ref: op://Dev/token/credential
  mine:
    account: personal
    env:
    - name: HOME_TOKEN
      ref: op://Private/token/credential
  team:
    account: team
    env:
    - name: TEAM_TOKEN
      ref: op://Private/team/credential
`

// testCLI returns an environment where OPB_CONFIG points at testConfig.
func testCLI(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opb.yaml")
	if err := os.WriteFile(path, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"OPB_CONFIG": path}
}

// execute runs opb with args and returns what cobra itself printed.
func execute(env map[string]string, args ...string) (string, error) {
	root := newRootCmd(&globals{getenv: func(k string) string { return env[k] }})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// complete returns the completions offered for args, without descriptions,
// and the directive line.
func complete(t *testing.T, env map[string]string, args ...string) ([]string, string) {
	t.Helper()
	out, err := execute(env, append([]string{"__complete"}, args...)...)
	if err != nil {
		t.Fatalf("__complete %q: %v", args, err)
	}
	var comps []string
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for _, l := range lines[:len(lines)-1] {
		name, _, _ := strings.Cut(l, "\t")
		comps = append(comps, name)
	}
	return comps, lines[len(lines)-1]
}

func TestCompletion(t *testing.T) {
	env := testCLI(t)
	tests := []struct {
		args []string
		want []string
	}{
		{[]string{"env", ""}, []string{"aws", "aws-ro", "db", "mine", "other", "team"}},
		// aws pins context work: bundles pinned elsewhere cannot be added.
		{[]string{"env", "aws", ""}, []string{"aws-ro", "db", "mine", "team"}},
		// mine pins account personal: bundles pinned to another account
		// cannot be added.
		{[]string{"env", "mine", ""}, []string{"aws", "aws-ro", "db", "other"}},
		{[]string{"--account", ""}, []string{"personal", "team"}},
		{[]string{"--account", "t"}, []string{"team"}},
		{[]string{"env", "a"}, []string{"aws", "aws-ro"}},
		{[]string{"run", "--bundle", "aws", "--bundle", ""}, []string{"aws-ro", "db", "mine", "team"}},
		{[]string{"context", "use", ""}, []string{"home", "work"}},
		{[]string{"context", "show", "w"}, []string{"work"}},
		{[]string{"context", "use", "work", ""}, nil},
		{[]string{"--context", ""}, []string{"home", "work"}},
		{[]string{"read", ""}, []string{"op://Dev/postgres/password", "op://Dev/token/credential", "op://Private/team/credential", "op://Private/token/credential", "op://Prod/aws-ro/access key id", "op://Prod/aws/access key id", "op://Prod/aws/secret access key"}},
		{[]string{"read", "op://Prod/aws/"}, []string{"op://Prod/aws/access key id", "op://Prod/aws/secret access key"}},
		{[]string{"read", "op://Nope"}, nil},
		{[]string{"item", "get", "--vault", ""}, []string{"Dev", "Private", "Prod"}},
		{[]string{"item", "get", "--vault", "Prod", ""}, []string{"aws", "aws-ro"}},
		{[]string{"item", "get", "--format", ""}, []string{"json"}},
		{[]string{"--server", ""}, []string{"http://op-broker.example.ts.net", "http://op-broker.corp.ts.net"}}, // in context order
		{[]string{"--broker", ""}, []string{"tag:op-broker"}},
		{[]string{"--broker", "u"}, []string{"user:"}},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			got, _ := complete(t, env, tt.args...)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCompletionOpPrefix(t *testing.T) {
	// Without a configuration file, references start with op://, which
	// must not be followed by a space.
	env := map[string]string{"OPB_CONFIG": filepath.Join(t.TempDir(), "missing.yaml")}
	got, directive := complete(t, env, "read", "")
	if !slices.Equal(got, []string{"op://"}) || directive != ":6" {
		t.Fatalf("got %q %s, want op:// :6 (no space, no files)", got, directive)
	}
	// A broken configuration offers nothing rather than failing.
	if got, _ := complete(t, env, "env", ""); got != nil {
		t.Fatalf("missing config: got %q", got)
	}
}

func TestCompletionScript(t *testing.T) {
	// Generating completion scripts must not need a valid configuration.
	env := map[string]string{"OPB_CONFIG": filepath.Join(t.TempDir(), "missing.yaml")}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		out, err := execute(env, "completion", shell)
		if err != nil || !strings.Contains(out, "opb") {
			t.Errorf("completion %s: %v, %d bytes", shell, err, len(out))
		}
	}
}

func TestUsageErrors(t *testing.T) {
	env := testCLI(t)
	for _, args := range [][]string{
		{},
		{"--context", "home"},
		{"read"},
		{"read", "a", "b"},
		{"inject", "extra"},
		{"run"},
		{"env"},
		{"item"},
		{"item", "bogus"},
		{"item", "get", "x"}, // --vault is required
		{"context"},
		{"context", "use"},
		{"context", "show", "a", "b"},
		{"read", "--bogus", "op://V/i/f"},
	} {
		_, err := execute(env, args...)
		if _, ok := errors.AsType[*usageError](err); !ok {
			t.Errorf("%q: %v, want a usage error", args, err)
		}
	}
}

func TestFlagsAfterArguments(t *testing.T) {
	// Flags may follow positional arguments, as with op.
	_, err := execute(testCLI(t), "item", "get", "postgres", "--vault", "Dev", "--format", "yaml")
	if err == nil || !strings.Contains(err.Error(), `unsupported format "yaml"`) {
		t.Fatalf("got %v, want an unsupported format error", err)
	}
}

func TestRunFlagsBelongToCommand(t *testing.T) {
	root := newRootCmd(&globals{getenv: func(string) string { return "" }})
	cmd, _, err := root.Find([]string{"run"})
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.ParseFlags([]string{"--bundle", "db", "ls", "--bundle", "x", "-l"}); err != nil {
		t.Fatal(err)
	}
	if got, want := cmd.Flags().Args(), []string{"ls", "--bundle", "x", "-l"}; !slices.Equal(got, want) {
		t.Fatalf("args = %q, want %q", got, want)
	}
	if got, _ := cmd.Flags().GetStringArray("bundle"); !slices.Equal(got, []string{"db"}) {
		t.Fatalf("bundles = %q, want [db]", got)
	}
}

func TestPinnedBundleRejectsFlags(t *testing.T) {
	// Global flags are seen wherever they appear on the command line.
	env := testCLI(t)
	for _, args := range [][]string{
		{"--server", "http://x", "env", "aws"},
		{"env", "aws", "--broker", "tag:x"},
		{"--allow-non-tailnet", "run", "--bundle", "aws", "--", "true"},
		{"run", "--server=http://x", "--bundle", "aws", "--", "true"},
		{"--context", "home", "env", "aws"},
	} {
		_, err := execute(env, args...)
		if err == nil || !strings.Contains(err.Error(), `context "work"`) {
			t.Errorf("%q: %v, want a pinned context error", args, err)
		}
	}
}

func TestPinnedAccountRejectsFlag(t *testing.T) {
	env := testCLI(t)
	for _, args := range [][]string{
		{"--account", "work", "env", "mine"},
		{"run", "--account=work", "--bundle", "mine", "--", "true"},
		{"env", "mine", "team"},
	} {
		_, err := execute(env, args...)
		if err == nil || !strings.Contains(err.Error(), "account") || !strings.Contains(err.Error(), `"personal"`) {
			t.Errorf("%q: %v, want a pinned account error", args, err)
		}
	}
}

func TestUnknownBundle(t *testing.T) {
	_, err := execute(testCLI(t), "run", "--bundle", "nope", "--", "true")
	if err == nil || !strings.Contains(err.Error(), `unknown bundle "nope"`) {
		t.Fatalf("got %v", err)
	}
}

// clearAmbientRefs removes references the real environment may hold.
func clearAmbientRefs(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, v, _ := strings.Cut(kv, "="); strings.HasPrefix(v, "op://") {
			t.Setenv(k, "")
		}
	}
}

func TestRunPinnedAccountRefusesForeignRefs(t *testing.T) {
	clearAmbientRefs(t)
	env := testCLI(t)
	t.Setenv("GITHUB_TOKEN", "op://Private/github/token")
	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("DB_PASSWORD=op://Private/db/password\nPLAIN=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := execute(env, "run", "--env-file", envFile, "--bundle", "mine", "--", "true")
	if err == nil {
		t.Fatal("run resolved environment references in the bundle's account")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"personal"`) || !strings.Contains(msg, "DB_PASSWORD, GITHUB_TOKEN") {
		t.Fatalf("error %q does not name the variables", msg)
	}
	if strings.Contains(msg, "op://") {
		t.Fatalf("error %q shows values", msg)
	}
}

// deniedServer answers every request with access denied and records the
// request bodies.
func deniedServer(t *testing.T) (*httptest.Server, *[]api.ResolveRequest) {
	t.Helper()
	var reqs []api.ResolveRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.ResolveRequest
		json.NewDecoder(r.Body).Decode(&req)
		reqs = append(reqs, req)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(api.ErrorBody{Error: api.ErrorDetail{Code: api.CodeDenied, Message: api.CodeDenied.Message()}})
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func TestRunAccountFlagAllowsEnvRefs(t *testing.T) {
	clearAmbientRefs(t)
	env := testCLI(t)
	t.Setenv("GITHUB_TOKEN", "op://Private/github/token")
	srv, reqs := deniedServer(t)
	for _, tt := range []struct {
		args []string
		want []string
	}{
		// The user chose the account for the whole command.
		{[]string{"--account", "personal", "run", "--bundle", "db", "--", "true"}, []string{"op://Private/github/token", "op://Dev/postgres/password"}},
		{[]string{"run", "--bundle", "db", "--", "true"}, []string{"op://Private/github/token", "op://Dev/postgres/password"}},
	} {
		*reqs = nil
		args := append([]string{"--allow-non-tailnet", "--server", srv.URL}, tt.args...)
		_, err := execute(env, args...)
		if ce, ok := errors.AsType[*client.Error](err); !ok || ce.Code != api.CodeDenied {
			t.Fatalf("%q: %v, want the server's denial", tt.args, err)
		}
		if len(*reqs) != 1 {
			t.Fatalf("%q: %d requests", tt.args, len(*reqs))
		}
		req := (*reqs)[0]
		wantAccount := ""
		if tt.args[0] == "--account" {
			wantAccount = "personal"
		}
		if req.Account != wantAccount || !slices.Equal(slices.Sorted(slices.Values(req.Refs)), slices.Sorted(slices.Values(tt.want))) {
			t.Fatalf("%q: request %+v", tt.args, req)
		}
	}

	// A pinned bundle overriding an ambient reference is fine.
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("HOME_TOKEN", "op://Private/stale/token")
	*reqs = nil
	_, err := execute(env, "--allow-non-tailnet", "--server", srv.URL, "run", "--bundle", "mine", "--", "true")
	if ce, ok := errors.AsType[*client.Error](err); !ok || ce.Code != api.CodeDenied {
		t.Fatalf("pinned bundle: %v, want the server's denial", err)
	}
	if len(*reqs) != 1 || (*reqs)[0].Account != "personal" || !slices.Equal((*reqs)[0].Refs, []string{"op://Private/token/credential"}) {
		t.Fatalf("pinned bundle: requests %+v", *reqs)
	}
}
