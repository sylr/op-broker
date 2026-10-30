// Package client talks to an opbd server and implements the opb commands.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/sylr/1password-broker/internal/api"
)

const (
	// DefaultServer is used when neither --server nor OPB_SERVER is set.
	DefaultServer = "http://op-broker"
	// Timeout bounds a whole request. It is longer than the server's request
	// deadline so that server-side errors are reported rather than cut off.
	Timeout = 150 * time.Second
	// maxResponseBytes bounds the response body read from the server.
	maxResponseBytes = 16 << 20
)

// Error is an error reported by the server.
type Error struct {
	Status int
	Code   api.Code
	Refs   []string
}

func (e *Error) Error() string {
	msg := e.Code.Message()
	if len(e.Refs) > 0 {
		msg += ": " + strings.Join(e.Refs, ", ")
	}
	return msg
}

// tailnetPrefixes are the address ranges Tailscale assigns to nodes.
var tailnetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// Options configures a Client.
type Options struct {
	// AllowNonTailnet allows connecting to addresses outside the Tailscale
	// ranges. By default the client refuses them, so that a server name
	// resolved through LAN DNS, mDNS or a search domain cannot impersonate
	// the broker when MagicDNS is unavailable.
	AllowNonTailnet bool
}

// Client is an opbd client.
type Client struct {
	base *url.URL
	hc   *http.Client
}

// New returns a client for the server at addr (a URL or a bare host name).
func New(addr string, opts Options) (*Client, error) {
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("invalid server address %q", addr)
	}
	return &Client{base: u, hc: newHTTPClient(opts)}, nil
}

// newHTTPClient returns an HTTP client that never uses a proxy (a proxy would
// see responses in clear and become the identity the server authorizes) and
// never follows redirects.
func newHTTPClient(opts Options) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !opts.AllowNonTailnet {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if !isTailnetAddr(ap.Addr()) {
				return fmt.Errorf("refusing to connect to %s: not a tailnet address", ap.Addr())
			}
			return nil
		}
	}
	return &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        1,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("refusing to follow redirect")
		},
	}
}

func isTailnetAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range tailnetPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Resolve returns the value of each ref, keyed by ref.
func (c *Client) Resolve(ctx context.Context, refs []string) (map[string]string, error) {
	var resp api.ResolveResponse
	body, err := c.post(ctx, "/v1/resolve", api.ResolveRequest{Refs: refs})
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decoding server response: %w", err)
	}
	for _, r := range refs {
		if _, ok := resp.Values[r]; !ok {
			return nil, fmt.Errorf("server response is missing %s", r)
		}
	}
	return resp.Values, nil
}

// Item returns the JSON representation of a whole item.
func (c *Client) Item(ctx context.Context, vault, item string) ([]byte, error) {
	return c.post(ctx, "/v1/item", api.ItemRequest{Vault: vault, Item: item})
}

func (c *Client) post(ctx context.Context, path string, reqBody any) ([]byte, error) {
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.JoinPath(path).String(), bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("server response too large")
	}
	if resp.StatusCode != http.StatusOK {
		var eb api.ErrorBody
		if json.Unmarshal(body, &eb) != nil || eb.Error.Code == "" {
			return nil, fmt.Errorf("server returned %s", resp.Status)
		}
		return nil, &Error{Status: resp.StatusCode, Code: eb.Error.Code, Refs: eb.Error.Refs}
	}
	return body, nil
}
