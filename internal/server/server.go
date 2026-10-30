// Package server implements the opbd HTTP API.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/sylr/1password-broker/internal/api"
	"github.com/sylr/1password-broker/internal/opcli"
	"github.com/sylr/1password-broker/internal/policy"
	"github.com/sylr/1password-broker/internal/ref"
)

// WhoIser identifies the tailnet node behind a remote address.
type WhoIser interface {
	WhoIs(ctx context.Context, remoteAddr string) (policy.Identity, error)
}

// Config configures a Server.
type Config struct {
	WhoIs  WhoIser
	Policy *policy.Policy
	Runner opcli.Runner
	Logger *slog.Logger
	// Hosts lists the accepted values of the Host header (names and IPs,
	// without port). Requests for any other host are rejected.
	Hosts []string
	// RequestTimeout bounds the whole handling of a request, including time
	// spent waiting for the op queue.
	RequestTimeout time.Duration
}

// Server serves the broker API.
type Server struct {
	whois          WhoIser
	runner         opcli.Runner
	log            *slog.Logger
	hosts          map[string]bool
	requestTimeout time.Duration
	policy         atomic.Pointer[policy.Policy]
	mux            *http.ServeMux
}

// New returns a server.
func New(cfg Config) *Server {
	s := &Server{
		whois:          cfg.WhoIs,
		runner:         cfg.Runner,
		log:            cfg.Logger,
		hosts:          make(map[string]bool),
		requestTimeout: cfg.RequestTimeout,
		mux:            http.NewServeMux(),
	}
	for _, h := range cfg.Hosts {
		s.hosts[normalizeHost(h)] = true
	}
	s.policy.Store(cfg.Policy)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	s.mux.HandleFunc("POST /v1/resolve", s.handleResolve)
	s.mux.HandleFunc("POST /v1/item", s.handleItem)
	return s
}

// SetPolicy atomically replaces the policy, e.g. on configuration reload.
func (s *Server) SetPolicy(p *policy.Policy) { s.policy.Store(p) }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// This is a CLI-only API: refuse anything a browser could send, and
	// any Host that is not ours (DNS rebinding).
	if r.Header.Get("Origin") != "" || !s.hosts[normalizeHost(r.Host)] {
		s.log.Info("access",
			slog.String("op", r.URL.Path),
			slog.String("remote", r.RemoteAddr),
			slog.String("decision", "error"),
			slog.String("code", string(api.CodeBadRequest)),
			slog.String("reason", "foreign origin or host"))
		writeError(w, api.CodeBadRequest, nil)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// whoisTimeout bounds the identification of a caller.
const whoisTimeout = 5 * time.Second

// event accumulates the fields of one audit log entry.
type event struct {
	start  time.Time
	remote string
	id     policy.Identity
	op     string
	refs   []string
}

func (s *Server) audit(e *event, decision string, code api.Code) {
	attrs := []any{
		slog.String("op", e.op),
		slog.String("remote", e.remote),
		slog.String("login", e.id.LoginName),
		slog.String("node_id", e.id.StableID),
		slog.String("node", e.id.NodeName),
		slog.Any("tags", e.id.Tags),
		slog.Any("refs", e.refs),
		slog.String("decision", decision),
		slog.Int64("duration_ms", time.Since(e.start).Milliseconds()),
	}
	if code != "" {
		attrs = append(attrs, slog.String("code", string(code)))
	}
	s.log.Info("access", attrs...)
}

// begin performs the checks common to API endpoints and identifies the
// caller. It returns false if a response has already been written.
func (s *Server) begin(ctx context.Context, w http.ResponseWriter, r *http.Request, e *event, dst any) bool {
	e.remote = r.RemoteAddr
	whoisCtx, cancel := context.WithTimeout(ctx, whoisTimeout)
	id, err := s.whois.WhoIs(whoisCtx, r.RemoteAddr)
	cancel()
	if err != nil {
		s.log.Error("whois failed", slog.String("remote", r.RemoteAddr), slog.String("error", err.Error()))
		s.audit(e, "error", api.CodeInternal)
		writeError(w, api.CodeInternal, nil)
		return false
	}
	e.id = id
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		s.audit(e, "error", api.CodeBadRequest)
		writeError(w, api.CodeBadRequest, nil)
		return false
	}
	if err := decodeStrict(w, r, dst); err != nil {
		s.audit(e, "error", api.CodeBadRequest)
		writeError(w, api.CodeBadRequest, nil)
		return false
	}
	return true
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	e := &event{start: time.Now(), op: "read-field"}
	ctx, cancel := context.WithTimeout(r.Context(), s.requestTimeout)
	defer cancel()
	var req api.ResolveRequest
	if !s.begin(ctx, w, r, e, &req) {
		return
	}
	if len(req.Refs) == 0 || len(req.Refs) > api.MaxRefs {
		s.audit(e, "error", api.CodeBadRequest)
		writeError(w, api.CodeBadRequest, nil)
		return
	}

	// Parse and de-duplicate. Several client strings may map to the same
	// canonical ref; each canonical ref is resolved once.
	byCanonical := make(map[string]ref.Ref)
	canonicalOf := make(map[string]string, len(req.Refs))
	seen := make(map[string]bool, len(req.Refs))
	var invalid []string
	for _, raw := range req.Refs {
		if seen[raw] {
			continue
		}
		seen[raw] = true
		parsed, err := ref.Parse(raw)
		if err != nil {
			invalid = append(invalid, raw)
			continue
		}
		c := parsed.String()
		canonicalOf[raw] = c
		if _, ok := byCanonical[c]; !ok {
			byCanonical[c] = parsed
			e.refs = append(e.refs, c)
		}
	}
	if len(invalid) > 0 {
		s.audit(e, "error", api.CodeBadRequest)
		writeError(w, api.CodeBadRequest, invalid)
		return
	}

	// Authorize every ref before running anything.
	pol := s.policy.Load()
	deniedCanonical := make(map[string]bool)
	for c, parsed := range byCanonical {
		if !pol.AllowField(e.id, parsed) {
			deniedCanonical[c] = true
		}
	}
	if len(deniedCanonical) > 0 {
		var denied []string
		for _, raw := range req.Refs {
			if c, ok := canonicalOf[raw]; ok && deniedCanonical[c] {
				denied = append(denied, raw)
				deniedCanonical[c] = false // report each once
			}
		}
		s.audit(e, "deny", api.CodeDenied)
		writeError(w, api.CodeDenied, denied)
		return
	}

	values := make(map[string]string, len(byCanonical))
	for _, c := range e.refs {
		out, err := s.runner.Read(ctx, byCanonical[c])
		if err != nil {
			code := runnerCode(err)
			s.audit(e, "error", code)
			writeError(w, code, nil)
			return
		}
		if !utf8.Valid(out) {
			s.audit(e, "error", api.CodeUnsupportedValue)
			writeError(w, api.CodeUnsupportedValue, nil)
			return
		}
		values[c] = string(out)
	}

	resp := api.ResolveResponse{Values: make(map[string]string, len(canonicalOf))}
	for raw, c := range canonicalOf {
		resp.Values[raw] = values[c]
	}
	s.audit(e, "allow", "")
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleItem(w http.ResponseWriter, r *http.Request) {
	e := &event{start: time.Now(), op: "read-item"}
	ctx, cancel := context.WithTimeout(r.Context(), s.requestTimeout)
	defer cancel()
	var req api.ItemRequest
	if !s.begin(ctx, w, r, e, &req) {
		return
	}
	if ref.ValidComponent(req.Vault) != nil || ref.ValidComponent(req.Item) != nil || req.Item == "-" {
		s.audit(e, "error", api.CodeBadRequest)
		writeError(w, api.CodeBadRequest, nil)
		return
	}
	e.refs = []string{"op://" + req.Vault + "/" + req.Item}
	if !s.policy.Load().AllowItem(e.id, req.Vault, req.Item) {
		s.audit(e, "deny", api.CodeDenied)
		writeError(w, api.CodeDenied, e.refs)
		return
	}

	out, err := s.runner.ItemGet(ctx, req.Vault, req.Item)
	if err != nil {
		code := runnerCode(err)
		s.audit(e, "error", code)
		writeError(w, code, nil)
		return
	}
	if !json.Valid(out) {
		s.audit(e, "error", api.CodeOpFailed)
		writeError(w, api.CodeOpFailed, nil)
		return
	}
	s.audit(e, "allow", "")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func runnerCode(err error) api.Code {
	if oe, ok := errors.AsType[*opcli.Error](err); ok {
		return oe.Code
	}
	return api.CodeInternal
}

// decodeStrict decodes exactly one JSON value with no unknown fields and no
// trailing data.
func decodeStrict(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, api.MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, code api.Code, refs []string) {
	writeJSON(w, code.Status(), api.ErrorBody{Error: api.ErrorDetail{
		Code:    code,
		Message: code.Message(),
		Refs:    refs,
	}})
}

func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	return strings.ToLower(h)
}
