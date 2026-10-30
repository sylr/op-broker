package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sylr/1password-broker/internal/api"
	"github.com/sylr/1password-broker/internal/opcli"
	"github.com/sylr/1password-broker/internal/policy"
	"github.com/sylr/1password-broker/internal/ref"
)

const sentinel = "SENTINEL-s3cr3t-9f2c"

var (
	laptop = policy.Identity{LoginName: "sylvain@formance.com", StableID: "nLAPTOP", NodeName: "laptop"}
	ciNode = policy.Identity{LoginName: "sylvain@formance.com", StableID: "nCI", NodeName: "ci", Tags: []string{"tag:ci"}}
)

type fakeWhoIs struct {
	byAddr map[string]policy.Identity
}

func (f fakeWhoIs) WhoIs(_ context.Context, addr string) (policy.Identity, error) {
	id, ok := f.byAddr[addr]
	if !ok {
		return policy.Identity{}, errors.New("no such peer")
	}
	return id, nil
}

type fakeRunner struct {
	mu     sync.Mutex
	values map[string]string   // canonical ref -> value
	errs   map[string]api.Code // canonical ref -> error
	items  map[string]string   // vault/item -> JSON
	calls  []string
}

func (f *fakeRunner) Read(_ context.Context, r ref.Ref) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.String())
	if code, ok := f.errs[r.String()]; ok {
		return nil, &opcli.Error{Code: code}
	}
	v, ok := f.values[r.String()]
	if !ok {
		return nil, &opcli.Error{Code: api.CodeNotFound}
	}
	return []byte(v), nil
}

func (f *fakeRunner) ItemGet(_ context.Context, vault, item string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "item:"+vault+"/"+item)
	v, ok := f.items[vault+"/"+item]
	if !ok {
		return nil, &opcli.Error{Code: api.CodeNotFound}
	}
	return []byte(v), nil
}

type harness struct {
	srv    *Server
	runner *fakeRunner
	logs   *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pol, err := policy.Compile([]policy.Rule{
		{Principals: []string{"user:sylvain@formance.com"}, Read: []string{"op://Dev/**"}, Items: []string{"op://Dev/postgres"}},
		{Principals: []string{"tag:ci"}, Read: []string{"op://CI/deploy/token"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{
		values: map[string]string{
			"op://Dev/postgres/password":                sentinel,
			"op://Dev/postgres/user":                    "  admin\n",
			"op://Dev/github/otp?attribute=otp":         "123456",
			"op://Dev/binary/file":                      "\xff\xfe",
			"op://CI/deploy/token":                      "ci-token",
			"op://Dev/postgres/conn/host":               "db.internal",
			"op://Dev/failing/password":                 "unused",
			"op://Dev/postgres/password?attribute=type": "CONCEALED",
		},
		errs: map[string]api.Code{
			"op://Dev/failing/password": api.CodeOpLocked,
		},
		items: map[string]string{
			"Dev/postgres": `{"id":"x","fields":[{"value":"` + sentinel + `"}]}`,
			"Dev/broken":   `not json ` + sentinel,
		},
	}
	logs := &bytes.Buffer{}
	srv := New(Config{
		WhoIs: fakeWhoIs{byAddr: map[string]policy.Identity{
			"100.64.0.1:1234": laptop,
			"100.64.0.2:1234": ciNode,
		}},
		Policy:         pol,
		Runner:         runner,
		Logger:         slog.New(slog.NewJSONHandler(logs, nil)),
		Hosts:          []string{"op-broker", "op-broker.tail1234.ts.net", "100.100.1.1"},
		RequestTimeout: 5 * time.Second,
	})
	t.Cleanup(func() {
		if strings.Contains(logs.String(), sentinel) {
			t.Errorf("secret value found in logs:\n%s", logs)
		}
	})
	return &harness{srv: srv, runner: runner, logs: logs}
}

type reqOpt func(*http.Request)

func from(addr string) reqOpt   { return func(r *http.Request) { r.RemoteAddr = addr } }
func header(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func host(h string) reqOpt      { return func(r *http.Request) { r.Host = h } }

func (h *harness) do(t *testing.T, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "100.64.0.1:1234"
	req.Host = "op-broker"
	req.Header.Set("Content-Type", "application/json")
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("missing Cache-Control: no-store")
	}
	return rec
}

func resolveBody(refs ...string) string {
	b, _ := json.Marshal(api.ResolveRequest{Refs: refs})
	return string(b)
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) api.ErrorDetail {
	t.Helper()
	if strings.Contains(rec.Body.String(), sentinel) {
		t.Fatalf("secret value found in error response: %s", rec.Body)
	}
	var body api.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body %q: %v", rec.Body, err)
	}
	if body.Error.Message != body.Error.Code.Message() {
		t.Fatalf("non-generic error message %q", body.Error.Message)
	}
	return body.Error
}

func decodeValues(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var resp api.ResolveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Values
}

func TestResolveAllowed(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Dev/postgres/password", "op://Dev/postgres/user"))
	values := decodeValues(t, rec)
	if values["op://Dev/postgres/password"] != sentinel {
		t.Fatalf("values = %v", values)
	}
	if values["op://Dev/postgres/user"] != "  admin\n" {
		t.Fatalf("whitespace not preserved: %q", values["op://Dev/postgres/user"])
	}
	if !strings.Contains(h.logs.String(), `"decision":"allow"`) {
		t.Fatalf("missing audit entry:\n%s", h.logs)
	}
}

func TestResolveDedupAndCanonical(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/resolve", resolveBody(
		"op://Dev/github/otp?attr=otp",
		"op://Dev/github/otp?attribute=otp",
		"op://Dev/github/otp?attr=otp",
	))
	values := decodeValues(t, rec)
	if len(values) != 2 || values["op://Dev/github/otp?attr=otp"] != "123456" || values["op://Dev/github/otp?attribute=otp"] != "123456" {
		t.Fatalf("values = %v", values)
	}
	if want := []string{"op://Dev/github/otp?attribute=otp"}; !slices.Equal(h.runner.calls, want) {
		t.Fatalf("runner calls = %v, want %v", h.runner.calls, want)
	}
}

func TestResolveDenied(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Prod/postgres/password"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if e := decodeError(t, rec); e.Code != api.CodeDenied || !slices.Equal(e.Refs, []string{"op://Prod/postgres/password"}) {
		t.Fatalf("error = %+v", e)
	}
	if len(h.runner.calls) != 0 {
		t.Fatalf("runner called for denied ref: %v", h.runner.calls)
	}
	if !strings.Contains(h.logs.String(), `"decision":"deny"`) {
		t.Fatalf("missing deny audit entry:\n%s", h.logs)
	}
}

func TestResolvePartialDenyRunsNothing(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Dev/postgres/password", "op://CI/deploy/token"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if e := decodeError(t, rec); !slices.Equal(e.Refs, []string{"op://CI/deploy/token"}) {
		t.Fatalf("denied refs = %v", e.Refs)
	}
	if len(h.runner.calls) != 0 {
		t.Fatalf("runner called although part of the batch was denied: %v", h.runner.calls)
	}
}

func TestResolveTaggedNodeDoesNotInheritCreator(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Dev/postgres/password"), from("100.64.0.2:1234"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	rec = h.do(t, "POST", "/v1/resolve", resolveBody("op://CI/deploy/token"), from("100.64.0.2:1234"))
	if values := decodeValues(t, rec); values["op://CI/deploy/token"] != "ci-token" {
		t.Fatalf("values = %v", values)
	}
}

func TestResolveFailureMidBatchReturnsNoValues(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Dev/postgres/password", "op://Dev/failing/password"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	if e := decodeError(t, rec); e.Code != api.CodeOpLocked {
		t.Fatalf("error = %+v", e)
	}
}

func TestResolveNotFound(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Dev/missing/password"))
	if rec.Code != http.StatusNotFound || decodeError(t, rec).Code != api.CodeNotFound {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestResolveBinaryValue(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Dev/binary/file"))
	if rec.Code != http.StatusUnprocessableEntity || decodeError(t, rec).Code != api.CodeUnsupportedValue {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestResolveBadRequests(t *testing.T) {
	tooMany := make([]string, api.MaxRefs+1)
	for i := range tooMany {
		tooMany[i] = "op://Dev/postgres/password"
	}
	tests := []struct {
		name string
		body string
		opts []reqOpt
	}{
		{"empty batch", resolveBody(), nil},
		{"null refs", `{"refs":null}`, nil},
		{"too many refs", resolveBody(tooMany...), nil},
		{"invalid ref", resolveBody("op://Dev/../password"), nil},
		{"unknown field", `{"refs":["op://Dev/postgres/password"],"as":"admin"}`, nil},
		{"trailing data", `{"refs":["op://Dev/postgres/password"]} {}`, nil},
		{"trailing garbage", `{"refs":["op://Dev/postgres/password"]}x`, nil},
		{"not json", `refs=op://Dev/postgres/password`, nil},
		{"body too large", `{"refs":["` + strings.Repeat("a", api.MaxBodyBytes) + `"]}`, nil},
		{"no content type", resolveBody("op://Dev/postgres/password"), []reqOpt{header("Content-Type", "")}},
		{"form content type", resolveBody("op://Dev/postgres/password"), []reqOpt{header("Content-Type", "text/plain")}},
		{"browser origin", resolveBody("op://Dev/postgres/password"), []reqOpt{header("Origin", "https://evil.example")}},
		{"foreign host", resolveBody("op://Dev/postgres/password"), []reqOpt{host("evil.example")}},
		{"rebinding host with port", resolveBody("op://Dev/postgres/password"), []reqOpt{host("evil.example:80")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			rec := h.do(t, "POST", "/v1/resolve", tt.body, tt.opts...)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
			}
			if e := decodeError(t, rec); e.Code != api.CodeBadRequest {
				t.Fatalf("error = %+v", e)
			}
			if len(h.runner.calls) != 0 {
				t.Fatalf("runner called: %v", h.runner.calls)
			}
		})
	}
}

func TestAcceptedHosts(t *testing.T) {
	for _, hst := range []string{"op-broker", "OP-BROKER:80", "op-broker.tail1234.ts.net.", "100.100.1.1:80"} {
		h := newHarness(t)
		rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Dev/postgres/user"), host(hst))
		if rec.Code != http.StatusOK {
			t.Errorf("Host %q: status = %d", hst, rec.Code)
		}
	}
}

func TestWhoIsFailure(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Dev/postgres/password"), from("192.0.2.1:1"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(h.runner.calls) != 0 {
		t.Fatalf("runner called for unidentified caller")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(t, "GET", "/v1/resolve", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "GET", "/healthz", "")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body)
	}
}

func itemBody(vault, item string) string {
	b, _ := json.Marshal(api.ItemRequest{Vault: vault, Item: item})
	return string(b)
}

func TestItem(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/v1/item", itemBody("Dev", "postgres"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), sentinel) {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestItemRequiresItemGrant(t *testing.T) {
	h := newHarness(t)
	// The caller may read every field under op://Dev/**, but has no items
	// grant for github.
	rec := h.do(t, "POST", "/v1/item", itemBody("Dev", "github"))
	if rec.Code != http.StatusForbidden || decodeError(t, rec).Code != api.CodeDenied {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if len(h.runner.calls) != 0 {
		t.Fatalf("runner called: %v", h.runner.calls)
	}
}

func TestItemBadInput(t *testing.T) {
	for _, tt := range []struct{ vault, item string }{
		{"Dev", "-"},
		{"Dev", ""},
		{"", "postgres"},
		{"Dev", "https://share.1password.com/s#abc"},
		{"Dev", "postgres/password"},
		{"Dev/x", "postgres"},
	} {
		h := newHarness(t)
		rec := h.do(t, "POST", "/v1/item", itemBody(tt.vault, tt.item))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q/%q: status = %d", tt.vault, tt.item, rec.Code)
		}
	}
}

func TestItemInvalidJSONFromOp(t *testing.T) {
	h := newHarness(t)
	h.srv.SetPolicy(mustPolicy(t, policy.Rule{Principals: []string{"user:sylvain@formance.com"}, Items: []string{"op://Dev/*"}}))
	rec := h.do(t, "POST", "/v1/item", itemBody("Dev", "broken"))
	if rec.Code != http.StatusBadGateway || decodeError(t, rec).Code != api.CodeOpFailed {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestSetPolicy(t *testing.T) {
	h := newHarness(t)
	h.srv.SetPolicy(mustPolicy(t, policy.Rule{Principals: []string{"user:someone@else"}, Read: []string{"op://**"}}))
	rec := h.do(t, "POST", "/v1/resolve", resolveBody("op://Dev/postgres/user"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reloaded policy not applied: status = %d", rec.Code)
	}
}

func mustPolicy(t *testing.T, rules ...policy.Rule) *policy.Policy {
	t.Helper()
	p, err := policy.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
