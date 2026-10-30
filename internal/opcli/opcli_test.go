package opcli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sylr/1password-broker/internal/api"
	"github.com/sylr/1password-broker/internal/ref"
)

const fakeOp = `#!/bin/sh
for last; do :; done
case "$last" in
  op://T/i/env) env ;;
  op://T/i/args) printf '%s\n' "$@" ;;
  op://T/i/notfound) echo '[ERROR] 2026/10/30 18:00:00 "i" isn'"'"'t an item in the "T" vault' >&2; exit 1 ;;
  op://T/i/dismissed) echo '[ERROR] 2026/10/30 18:04:35 authorization prompt dismissed, please try again' >&2; exit 1 ;;
  op://T/i/weird) echo 'something unexpected: s3cr3t' >&2; exit 1 ;;
  op://T/i/sleep) sleep 5 ;;
  op://T/i/big) head -c 2000000 /dev/zero ;;
  op://T/i/serial) echo start >> "$LOGFILE"; sleep 0.1; echo end >> "$LOGFILE"; printf v ;;
  item) printf '%s\n' "$@" ;;
  *) printf 'secret' ;;
esac
`

func newFake(t *testing.T, timeout time.Duration) (*Exec, string) {
	t.Helper()
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log")
	script := strings.ReplaceAll(fakeOp, `"$LOGFILE"`, `"`+logFile+`"`)
	path := filepath.Join(dir, "op")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return NewExec(path, "ACCOUNT123", timeout), logFile
}

func read(t *testing.T, e *Exec, s string) ([]byte, error) {
	t.Helper()
	r, err := ref.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return e.Read(context.Background(), r)
}

func code(t *testing.T, err error) api.Code {
	t.Helper()
	var oe *Error
	if !errors.As(err, &oe) {
		t.Fatalf("error %v is not an *opcli.Error", err)
	}
	return oe.Code
}

func TestReadSuccess(t *testing.T) {
	e, _ := newFake(t, 5*time.Second)
	out, err := read(t, e, "op://T/i/anything")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "secret" {
		t.Fatalf("got %q", out)
	}
}

func TestReadArgs(t *testing.T) {
	e, _ := newFake(t, 5*time.Second)
	out, err := read(t, e, "op://T/i/args")
	if err != nil {
		t.Fatal(err)
	}
	want := "read\n--account=ACCOUNT123\n--no-newline\n--\nop://T/i/args\n"
	if string(out) != want {
		t.Fatalf("args = %q, want %q", out, want)
	}
}

func TestItemGetArgs(t *testing.T) {
	e, _ := newFake(t, 5*time.Second)
	out, err := e.ItemGet(context.Background(), "Dev", "item")
	if err != nil {
		t.Fatal(err)
	}
	want := "item\nget\n--account=ACCOUNT123\n--vault=Dev\n--format=json\n--\nitem\n"
	if string(out) != want {
		t.Fatalf("args = %q, want %q", out, want)
	}
}

func TestCleanEnvironment(t *testing.T) {
	for _, k := range []string{"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_SESSION_abc", "OP_CONFIG_DIR", "OP_DEBUG", "OP_ACCOUNT", "LEAKME"} {
		t.Setenv(k, "polluted")
	}
	e, _ := newFake(t, 5*time.Second)
	out, err := read(t, e, "op://T/i/env")
	if err != nil {
		t.Fatal(err)
	}
	env := string(out)
	if strings.Contains(env, "polluted") {
		t.Fatalf("parent environment leaked into op:\n%s", env)
	}
	if !strings.Contains(env, "OP_BIOMETRIC_UNLOCK_ENABLED=true") {
		t.Fatalf("desktop integration not enabled:\n%s", env)
	}
}

func TestBuildEnv(t *testing.T) {
	env := BuildEnv(func(k string) string {
		return map[string]string{"HOME": "/h", "USER": "u", "OP_SERVICE_ACCOUNT_TOKEN": "x"}[k]
	})
	want := []string{"HOME=/h", "USER=u", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=en_US.UTF-8", "OP_BIOMETRIC_UNLOCK_ENABLED=true"}
	if strings.Join(env, ",") != strings.Join(want, ",") {
		t.Fatalf("BuildEnv = %v, want %v", env, want)
	}
}

func TestErrors(t *testing.T) {
	e, _ := newFake(t, 300*time.Millisecond)
	tests := []struct {
		ref  string
		want api.Code
	}{
		{"op://T/i/notfound", api.CodeNotFound},
		{"op://T/i/dismissed", api.CodeOpLocked},
		{"op://T/i/weird", api.CodeOpFailed},
		{"op://T/i/sleep", api.CodeTimeout},
		{"op://T/i/big", api.CodeOpFailed},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			_, err := read(t, e, tt.ref)
			if got := code(t, err); got != tt.want {
				t.Fatalf("code = %s, want %s", got, tt.want)
			}
			if strings.Contains(err.Error(), "s3cr3t") {
				t.Fatalf("error exposes op output: %v", err)
			}
		})
	}
}

func TestCancelledContext(t *testing.T) {
	e, _ := newFake(t, 5*time.Second)
	r, _ := ref.Parse("op://T/i/sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := e.Read(ctx, r)
	if code(t, err) != api.CodeTimeout {
		t.Fatalf("got %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("cancellation took %s", d)
	}
}

func TestSerialized(t *testing.T) {
	e, logFile := newFake(t, 5*time.Second)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if _, err := read(t, e, "op://T/i/serial"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	b, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("start\nend\n", 4)
	if string(b) != want {
		t.Fatalf("op invocations overlapped:\n%s", b)
	}
}

func TestQueueFull(t *testing.T) {
	e, _ := newFake(t, 5*time.Second)
	e.waiting.Store(MaxWaiting)
	_, err := read(t, e, "op://T/i/anything")
	if code(t, err) != api.CodeBusy {
		t.Fatalf("got %v", err)
	}
}

func TestClassifyIgnoresCallerNames(t *testing.T) {
	tests := []struct {
		stderr string
		names  []string
		want   api.Code
	}{
		{
			`[ERROR] 2026/10/30 18:22:04 could not read secret 'op://Dev/Door is locked/code': could not get item Dev/Door is locked: "Door is locked" isn't an item in the "Dev" vault.`,
			[]string{"op://Dev/Door is locked/code", "Dev/Door is locked"},
			api.CodeNotFound,
		},
		{
			`[ERROR] could not read secret 'op://Dev/authorization prompt dismissed/x': could not get item Dev/authorization prompt dismissed: something went wrong`,
			[]string{"op://Dev/authorization prompt dismissed/x", "Dev/authorization prompt dismissed"},
			api.CodeOpFailed,
		},
		{
			`[ERROR] could not get item Dev/isn't an item: unexpected failure`,
			[]string{"Dev/isn't an item"},
			api.CodeOpFailed,
		},
	}
	for _, tt := range tests {
		if got := Classify(tt.stderr, tt.names...); got != tt.want {
			t.Errorf("Classify(%q) = %s, want %s", tt.stderr, got, tt.want)
		}
	}
}

func TestClassify(t *testing.T) {
	tests := map[string]api.Code{
		"[ERROR] authorization prompt dismissed, please try again":                                                                                     api.CodeOpLocked,
		"[ERROR] connecting to desktop app: 1Password CLI couldn't connect to the 1Password desktop app":                                               api.CodeOpLocked,
		`[ERROR] "Nope" isn't a vault in this account. Specify the vault with its ID or name.`:                                                         api.CodeNotFound,
		`[ERROR] could not read secret 'op://Dev/x/y': "y" isn't a field in the "x" item`:                                                              api.CodeNotFound,
		`[ERROR] 2026/10/30 18:22:03 could not read secret 'op://Employee/Pwet/nosuchfield': item 'Employee/Pwet' does not have a field 'nosuchfield'`: api.CodeNotFound,
		`[ERROR] could not get item Employee/NoSuchItemXyz: "NoSuchItemXyz" isn't an item in the "Employee" vault.`:                                    api.CodeNotFound,
		"[ERROR] something else": api.CodeOpFailed,
		"":                       api.CodeOpFailed,
	}
	for in, want := range tests {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q) = %s, want %s", in, got, want)
		}
	}
}
