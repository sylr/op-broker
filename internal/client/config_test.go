package client

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const testConfig = `# opb configuration
current_context: home   # the default

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

func mustParseConfig(t *testing.T, s string) *Config {
	t.Helper()
	cfg, err := ParseConfig([]byte(s))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	return cfg
}

func TestParseConfig(t *testing.T) {
	cfg := mustParseConfig(t, testConfig)
	if cfg.CurrentContext != "home" || len(cfg.Contexts) != 2 || len(cfg.Bundles) != 4 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if got := cfg.Contexts["work"].Broker; got != "tag:op-broker" {
		t.Fatalf("work broker = %q", got)
	}
	if empty := mustParseConfig(t, ""); empty.CurrentContext != "" || empty.Contexts != nil {
		t.Fatalf("empty config = %+v", empty)
	}
}

func TestParseConfigErrors(t *testing.T) {
	tests := []struct {
		name, doc string
	}{
		{"unknown key", "contexts: {}\nbogus: 1\n"},
		{"unknown context key", "contexts:\n  a:\n    sever: x\n"},
		{"unknown current context", "current_context: nope\n"},
		{"bad context name", "contexts:\n  'a b':\n    server: x\n"},
		{"bad broker", "contexts:\n  a:\n    server: x\n    broker: group:x\n"},
		{"context without server", "contexts:\n  a:\n    allow_non_tailnet: true\n"},
		{"bundle unknown context", "bundles:\n  b:\n    context: nope\n    env: [{name: A, ref: op://V/i/f}]\n"},
		{"bad bundle name", "bundles:\n  '-b':\n    env: [{name: A, ref: op://V/i/f}]\n"},
		{"empty bundle", "bundles:\n  b:\n    env: []\n"},
		{"bad env name", "bundles:\n  b:\n    env: [{name: 1A, ref: op://V/i/f}]\n"},
		{"bad ref", "bundles:\n  b:\n    env: [{name: A, ref: op://V/i}]\n"},
		{"duplicate env name", "bundles:\n  b:\n    env: [{name: A, ref: op://V/i/f}, {name: A, ref: op://V/i/g}]\n"},
		{"second document", "contexts: {}\n---\ncurrent_context: x\n"},
		{"bad context account", "contexts:\n  a:\n    server: x\n    account: Work\n"},
		{"context account UUID", "contexts:\n  a:\n    server: x\n    account: ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"},
		{"bad bundle account", "bundles:\n  b:\n    account: 'work account'\n    env: [{name: A, ref: op://V/i/f}]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(tt.doc)); err == nil {
				t.Fatal("ParseConfig succeeded, want error")
			}
		})
	}
}

func TestSelectContext(t *testing.T) {
	cfg := mustParseConfig(t, testConfig)
	tests := []struct {
		name           string
		flag, env, pin string
		want           string
		wantErr        bool
	}{
		{"current_context", "", "", "", "home", false},
		{"env over current", "", "work", "", "work", false},
		{"flag over env", "home", "work", "", "home", false},
		{"pin over env", "", "home", "work", "work", false},
		{"pin agrees with flag", "work", "", "work", "work", false},
		{"pin conflicts with flag", "home", "", "work", "", true},
		{"unknown", "nope", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := cfg.SelectContext(tt.flag, tt.env, tt.pin)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("SelectContext = %q, %v; want %q, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
	if name, _, err := (&Config{}).SelectContext("", "", ""); name != "" || err != nil {
		t.Fatalf("empty config: %q, %v", name, err)
	}
}

func TestBundleEnv(t *testing.T) {
	cfg := mustParseConfig(t, testConfig)

	vars, pin, err := cfg.BundleEnv([]string{"db", "aws", "aws-ro"})
	if err != nil {
		t.Fatal(err)
	}
	if pin != (Pin{Context: "work"}) {
		t.Fatalf("pin = %+v, want context work", pin)
	}
	got := MergeEnv(nil, vars)
	want := []string{
		"PGPASSWORD=op://Dev/postgres/password",
		"AWS_ACCESS_KEY_ID=op://Prod/aws-ro/access key id", // later bundle wins
		"AWS_SECRET_ACCESS_KEY=op://Prod/aws/secret access key",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("env = %q, want %q", got, want)
	}

	if _, pin, _ := cfg.BundleEnv([]string{"db"}); pin != (Pin{}) {
		t.Fatalf("unpinned bundle pinned %+v", pin)
	}
	if _, _, err := cfg.BundleEnv([]string{"aws", "other"}); err == nil {
		t.Fatal("bundles pinned to different contexts were combined")
	}
	if _, _, err := cfg.BundleEnv([]string{"nope"}); err == nil {
		t.Fatal("unknown bundle accepted")
	}
}

func TestBundleAccounts(t *testing.T) {
	cfg := mustParseConfig(t, `
contexts:
  home:
    server: http://home
    account: personal
bundles:
  db:
    env: [{name: A, ref: op://V/i/a}]
  mine:
    account: personal
    env: [{name: B, ref: op://V/i/b}]
  mine-too:
    context: home
    account: personal
    env: [{name: C, ref: op://V/i/c}]
  theirs:
    account: work
    env: [{name: D, ref: op://V/i/d}]
`)
	if got := cfg.Contexts["home"].Account; got != "personal" {
		t.Fatalf("context account = %q", got)
	}
	_, pin, err := cfg.BundleEnv([]string{"db", "mine", "mine-too"})
	if err != nil {
		t.Fatal(err)
	}
	if pin != (Pin{Context: "home", Account: "personal"}) {
		t.Fatalf("pin = %+v", pin)
	}
	if _, _, err := cfg.BundleEnv([]string{"mine", "theirs"}); err == nil {
		t.Fatal("bundles pinned to different accounts were combined")
	}
}

func TestSetCurrentContext(t *testing.T) {
	tests := []struct {
		name, doc, want string
	}{
		{
			"replace keeps comments",
			testConfig,
			strings.Replace(testConfig, "current_context: home   # the default\n", "current_context: \"work\" # the default\n", 1),
		},
		{
			"append when absent",
			"contexts:\n  work: {server: x}\n# trailing comment",
			"contexts:\n  work: {server: x}\n# trailing comment\ncurrent_context: \"work\"\n",
		},
		{
			"crlf kept",
			"current_context: \"\"\r\ncontexts:\r\n  work: {server: x}\r\n",
			"current_context: \"work\"\r\ncontexts:\r\n  work: {server: x}\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := setCurrentContext([]byte(tt.doc), "work")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("got:\n%s\nwant:\n%s", got, tt.want)
			}
			if cfg := mustParseConfig(t, string(got)); cfg.CurrentContext != "work" {
				t.Fatalf("current_context = %q", cfg.CurrentContext)
			}
		})
	}

	for name, doc := range map[string]string{
		"unknown context": testConfig,
		"flow mapping":    "{contexts: {nope: {server: x}}}",
		"multi-line":      "current_context: >-\n  nope\ncontexts:\n  nope: {server: x}\n",
		"lone CR":         "contexts:\r  nope: {server: x}\r  home: {server: x}\rcurrent_context: home\r",
		"CR in comment":   "# a\rb\ncurrent_context: home\ncontexts:\n  nope: {server: x}\n  home: {server: x}\n",
		"CR after key":    "contexts:\n  home: {server: x}\n  nope: {server: x}\ncurrent_context: home\rbundles:\r  b:\r    env: [{name: A, ref: op://v/i/f}]\n",
		"line separator":  "current_context: home\u2028contexts:\n  home: {server: x}\n  nope: {server: x}\n",
		"indented root":   "  current_context: home\n  contexts:\n    nope: {server: x}\n    home: {server: x}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := setCurrentContext([]byte(doc), "nope"); err == nil {
				t.Fatal("setCurrentContext succeeded, want error")
			}
		})
	}
}

func TestSetCurrentContextFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opb.yaml")
	if err := os.WriteFile(path, []byte(testConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	// The file is re-validated before it is written: appending after a
	// document end marker is caught.
	ended := filepath.Join(dir, "ended.yaml")
	if err := os.WriteFile(ended, []byte("contexts:\n  work: {server: x}\n...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(ended, "work"); err == nil {
		t.Fatal("append after a document end marker accepted")
	}
	if err := SetCurrentContext(path, "nope"); err == nil {
		t.Fatal("unknown context accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != testConfig {
		t.Fatal("file changed after a failed update")
	}
	if err := SetCurrentContext(path, "work"); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CurrentContext != "work" {
		t.Fatalf("current_context = %q", cfg.CurrentContext)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode after update: %v, %v; want 0644", fi.Mode().Perm(), err)
	}

	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentContext(link, "home"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("write through symlink: %v", err)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.yaml")
	if cfg, err := LoadConfig(missing, false); err != nil || cfg == nil {
		t.Fatalf("missing default config: %v", err)
	}
	if _, err := LoadConfig(missing, true); err == nil {
		t.Fatal("missing explicit config accepted")
	}

	path := filepath.Join(dir, "opb.yaml")
	if err := os.WriteFile(path, []byte(testConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link, true); err != nil {
		t.Fatalf("symlinked config: %v", err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path, true); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("group-writable config: %v", err)
	}
	if err := os.WriteFile(path, []byte("bogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path, false); err == nil {
		t.Fatal("invalid config accepted")
	}

	dangling := filepath.Join(dir, "dangling.yaml")
	if err := os.Symlink(filepath.Join(dir, "gone.yaml"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(dangling, false); err == nil {
		t.Fatal("dangling symlink treated as a missing config")
	}
}

func TestParseConfigSyntaxErrorAfterDocument(t *testing.T) {
	_, err := ParseConfig([]byte("contexts: {}\n---\n: [\n"))
	if err == nil || strings.Contains(err.Error(), "only one YAML document") {
		t.Fatalf("syntax error reported as %v", err)
	}
}
