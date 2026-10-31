package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
		{[]string{"env", ""}, []string{"aws", "aws-ro", "db", "other"}},
		// aws pins context work: bundles pinned elsewhere cannot be added.
		{[]string{"env", "aws", ""}, []string{"aws-ro", "db"}},
		{[]string{"env", "a"}, []string{"aws", "aws-ro"}},
		{[]string{"run", "--bundle", "aws", "--bundle", ""}, []string{"aws-ro", "db"}},
		{[]string{"context", "use", ""}, []string{"home", "work"}},
		{[]string{"context", "show", "w"}, []string{"work"}},
		{[]string{"context", "use", "work", ""}, nil},
		{[]string{"--context", ""}, []string{"home", "work"}},
		{[]string{"read", ""}, []string{"op://Dev/postgres/password", "op://Dev/token/credential", "op://Prod/aws-ro/access key id", "op://Prod/aws/access key id", "op://Prod/aws/secret access key"}},
		{[]string{"read", "op://Prod/aws/"}, []string{"op://Prod/aws/access key id", "op://Prod/aws/secret access key"}},
		{[]string{"read", "op://Nope"}, nil},
		{[]string{"item", "get", "--vault", ""}, []string{"Dev", "Prod"}},
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

func TestUnknownBundle(t *testing.T) {
	_, err := execute(testCLI(t), "run", "--bundle", "nope", "--", "true")
	if err == nil || !strings.Contains(err.Error(), `unknown bundle "nope"`) {
		t.Fatalf("got %v", err)
	}
}
