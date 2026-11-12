package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sylr/op-broker/internal/api"
	"github.com/sylr/op-broker/internal/config"
	"github.com/sylr/op-broker/internal/opcli"
	"github.com/sylr/op-broker/internal/policy"
)

// These tests go through the real opcli.Exec with a fake op binary.

const fakeOp = `#!/bin/sh
for last; do :; done
case "$last" in
  op://Dev/slow/x) sleep 5 ;;
  op://Dev/leak/x) echo "[ERROR] unexpected: ` + sentinel + `" >&2; exit 1 ;;
  *) printf ok ;;
esac
`

func newExecServer(t *testing.T, requestTimeout time.Duration) (*Server, *bytes.Buffer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "op")
	if err := os.WriteFile(path, []byte(fakeOp), 0o700); err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	t.Cleanup(func() {
		if strings.Contains(logs.String(), sentinel) {
			t.Errorf("secret value found in logs:\n%s", logs)
		}
	})
	return New(Config{
		WhoIs:          fakeWhoIs{byAddr: map[string]policy.Identity{"100.64.0.1:1234": laptop}},
		Policy:         mustPolicy(t, policy.Rule{Principals: []string{"user:sylvain@formance.com"}, Read: []string{"op://Dev/**"}}),
		Runner:         opcli.NewExec(path, 10*time.Second),
		Accounts:       testAccounts,
		DefaultAccount: "work",
		Logger:         slog.New(slog.NewJSONHandler(logs, nil)),
		Hosts:          []string{"op-broker"},
		RequestTimeout: requestTimeout,
	}), logs
}

func post(srv *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/v1/resolve", strings.NewReader(body))
	req.RemoteAddr = "100.64.0.1:1234"
	req.Host = "op-broker"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestRequestDeadline(t *testing.T) {
	srv, _ := newExecServer(t, 300*time.Millisecond)
	start := time.Now()
	rec := post(srv, resolveBody("op://Dev/slow/x"))
	if rec.Code != http.StatusGatewayTimeout || decodeError(t, rec).Code != api.CodeTimeout {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("request deadline not enforced: took %s", d)
	}
}

func TestOpStderrNeverExposed(t *testing.T) {
	srv, _ := newExecServer(t, 5*time.Second)
	rec := post(srv, resolveBody("op://Dev/leak/x"))
	if rec.Code != http.StatusBadGateway || decodeError(t, rec).Code != api.CodeOpFailed {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestRejectedHostIsAudited(t *testing.T) {
	srv, logs := newExecServer(t, 5*time.Second)
	req := httptest.NewRequest("POST", "/v1/resolve", strings.NewReader(resolveBody("op://Dev/a/b")))
	req.RemoteAddr = "100.64.0.9:1"
	req.Host = "evil.example"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(logs.String(), `"remote":"100.64.0.9:1"`) {
		t.Fatalf("rejected request not audited:\n%s", logs)
	}
}

// TestAccountsEndToEnd goes from the configuration file to the op command
// line: the fake op prints the --account argument it was given.
func TestAccountsEndToEnd(t *testing.T) {
	cfg, pol, err := config.Parse([]byte(`
op:
  accounts:
    work: ` + workUUID + `
    personal: ` + personalUUID + `
  default_account: work
rules:
  - principals: ["user:sylvain@formance.com"]
    read: ["op://Dev/**"]
  - principals: ["user:sylvain@formance.com"]
    accounts: [work]
    read: ["op://Ops/**"]
`))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "op")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s' \"$2\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	srv := New(Config{
		WhoIs:          fakeWhoIs{byAddr: map[string]policy.Identity{"100.64.0.1:1234": laptop}},
		Policy:         pol,
		Runner:         opcli.NewExec(path, 10*time.Second),
		Accounts:       cfg.Op.Accounts,
		DefaultAccount: cfg.Op.DefaultAccount,
		Logger:         slog.New(slog.NewJSONHandler(logs, nil)),
		Hosts:          []string{"op-broker"},
		RequestTimeout: 5 * time.Second,
	})
	h := &harness{srv: srv, logs: logs}

	// The rule without accounts and the rule naming the default account
	// both apply to the default account, whether named or implied.
	for _, account := range []string{"", "work"} {
		rec := h.do(t, "POST", "/v1/resolve", resolveBodyIn(account, "op://Dev/a/b", "op://Ops/c/d"))
		values := decodeValues(t, rec)
		for _, r := range []string{"op://Dev/a/b", "op://Ops/c/d"} {
			if values[r] != "--account="+workUUID {
				t.Errorf("account %q: %s resolved with %q", account, r, values[r])
			}
		}
	}
	// Neither applies to the other account.
	for _, r := range []string{"op://Dev/a/b", "op://Ops/c/d"} {
		rec := h.do(t, "POST", "/v1/resolve", resolveBodyIn("personal", r))
		if rec.Code != http.StatusForbidden || decodeError(t, rec).Code != api.CodeDenied {
			t.Errorf("personal %s: status = %d, body = %s", r, rec.Code, rec.Body)
		}
	}
	if !strings.Contains(logs.String(), `"account":"work"`) || !strings.Contains(logs.String(), `"account":"personal"`) {
		t.Errorf("accounts missing from audit log:\n%s", logs)
	}
}
