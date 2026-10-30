package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"github.com/sylr/op-broker/internal/api"
)

// loopback allows the httptest servers, which listen on loopback.
var loopback = Options{AllowNonTailnet: true}

func TestRefusesNonTailnetAddress(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	c, err := New(srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Resolve(context.Background(), []string{"op://a/b/c"}); err == nil {
		t.Fatal("connected to a non-tailnet address")
	}
	if hits != 0 {
		t.Fatal("request reached a non-tailnet server")
	}
}

func TestVerifierGatesEveryConnection(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		json.NewEncoder(w).Encode(api.ResolveResponse{Values: map[string]string{"op://a/b/c": "v"}})
	}))
	defer srv.Close()

	var verified []string
	reject := Options{AllowNonTailnet: true, Verify: func(_ context.Context, addr string) error {
		verified = append(verified, addr)
		return errors.New("not the broker")
	}}
	c, _ := New(srv.URL, reject)
	if _, err := c.Resolve(context.Background(), []string{"op://a/b/c"}); err == nil {
		t.Fatal("request sent to an unverified peer")
	}
	if hits != 0 {
		t.Fatal("unverified peer received the request")
	}
	if len(verified) != 1 || verified[0] != srv.Listener.Addr().String() {
		t.Fatalf("verifier called with %v, want the connected address %s", verified, srv.Listener.Addr())
	}

	accept := Options{AllowNonTailnet: true, Verify: func(context.Context, string) error { return nil }}
	c, _ = New(srv.URL, accept)
	if _, err := c.Resolve(context.Background(), []string{"op://a/b/c"}); err != nil {
		t.Fatal(err)
	}
}

func TestIsTailnetAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"100.64.0.1":         true,
		"100.127.255.254":    true,
		"::ffff:100.100.1.1": true,
		"fd7a:115c:a1e0::1":  true,
		"100.128.0.1":        false,
		"192.168.1.10":       false,
		"127.0.0.1":          false,
		"fd7a:115c:a1e1::1":  false,
		"2001:db8::1":        false,
	} {
		if got := isTailnetAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isTailnetAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestTransportIgnoresProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	tr, ok := newHTTPClient(Options{}).Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport type")
	}
	if tr.Proxy != nil {
		t.Fatal("transport uses a proxy function")
	}
}

func TestResolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/resolve" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request %s %s", r.URL.Path, r.Header.Get("Content-Type"))
		}
		var req api.ResolveRequest
		json.NewDecoder(r.Body).Decode(&req)
		values := map[string]string{}
		for _, ref := range req.Refs {
			values[ref] = "v:" + ref
		}
		json.NewEncoder(w).Encode(api.ResolveResponse{Values: values})
	}))
	defer srv.Close()

	c, err := New(srv.URL, loopback)
	if err != nil {
		t.Fatal(err)
	}
	values, err := c.Resolve(context.Background(), []string{"op://a/b/c"})
	if err != nil {
		t.Fatal(err)
	}
	if values["op://a/b/c"] != "v:op://a/b/c" {
		t.Fatalf("values = %v", values)
	}
}

func TestResolveMissingValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.ResolveResponse{Values: map[string]string{}})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, loopback)
	if _, err := c.Resolve(context.Background(), []string{"op://a/b/c"}); err == nil {
		t.Fatal("incomplete response accepted")
	}
}

func TestServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(api.ErrorBody{Error: api.ErrorDetail{Code: api.CodeDenied, Message: "x", Refs: []string{"op://a/b/c"}}})
	}))
	defer srv.Close()
	c, _ := New(srv.URL, loopback)
	_, err := c.Resolve(context.Background(), []string{"op://a/b/c"})
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != api.CodeDenied || !slices.Equal(ce.Refs, []string{"op://a/b/c"}) {
		t.Fatalf("err = %#v", err)
	}
}

func TestRefusesRedirect(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/resolve", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, loopback)
	if _, err := c.Resolve(context.Background(), []string{"op://a/b/c"}); err == nil {
		t.Fatal("redirect followed")
	}
	if hits != 0 {
		t.Fatal("redirect target was contacted")
	}
}

func TestNewAddress(t *testing.T) {
	for _, ok := range []string{"op-broker", "http://op-broker", "op-broker.tail1234.ts.net:8080", "https://op-broker.tail1234.ts.net"} {
		if _, err := New(ok, Options{}); err != nil {
			t.Errorf("New(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"ftp://op-broker", "http://", "http://user:pw@op-broker"} {
		if _, err := New(bad, Options{}); err == nil {
			t.Errorf("New(%q) succeeded", bad)
		}
	}
}
