// Package opcli runs the 1Password CLI on behalf of the server.
//
// Every invocation goes through a single global queue so that concurrent
// requests never trigger concurrent desktop-app approval prompts. The child
// process gets an environment built from scratch: alternate authentication
// backends (service accounts, Connect, session tokens) and debug settings of
// the parent are never passed through.
package opcli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sylr/op-broker/internal/api"
	"github.com/sylr/op-broker/internal/ref"
)

const (
	// MaxStdout bounds the output accepted from op.
	MaxStdout = 1 << 20
	// MaxStderr bounds the diagnostics kept for classification.
	MaxStderr = 64 << 10
	// MaxWaiting bounds the number of calls waiting in the queue.
	MaxWaiting = 32
)

// Runner resolves secrets.
type Runner interface {
	// Read returns the value of a field.
	Read(ctx context.Context, r ref.Ref) ([]byte, error)
	// ItemGet returns the JSON representation of a whole item.
	ItemGet(ctx context.Context, vault, item string) ([]byte, error)
}

// Error is returned by Exec for every failure. It only carries a code: the
// raw output of op is never exposed.
type Error struct {
	Code api.Code
}

func (e *Error) Error() string { return "op: " + string(e.Code) }

// Exec runs the op binary.
type Exec struct {
	path    string
	account string
	timeout time.Duration
	env     []string

	sem     chan struct{}
	waiting atomic.Int32
}

// NewExec returns a runner using the op binary at path, pinned to account.
// Each invocation is limited to timeout.
func NewExec(path, account string, timeout time.Duration) *Exec {
	return &Exec{
		path:    path,
		account: account,
		timeout: timeout,
		env:     BuildEnv(os.Getenv),
		sem:     make(chan struct{}, 1),
	}
}

// BuildEnv returns the environment for op processes. Only a fixed set of
// variables is taken from getenv.
func BuildEnv(getenv func(string) string) []string {
	lang := getenv("LANG")
	if lang == "" {
		lang = "en_US.UTF-8"
	}
	return []string{
		"HOME=" + getenv("HOME"),
		"USER=" + getenv("USER"),
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LANG=" + lang,
		"OP_BIOMETRIC_UNLOCK_ENABLED=true",
	}
}

// Read implements Runner.
func (e *Exec) Read(ctx context.Context, r ref.Ref) ([]byte, error) {
	return e.run(ctx, []string{r.String(), r.Vault + "/" + r.Item}, "read", "--account="+e.account, "--no-newline", "--", r.String())
}

// ItemGet implements Runner.
func (e *Exec) ItemGet(ctx context.Context, vault, item string) ([]byte, error) {
	return e.run(ctx, []string{vault + "/" + item}, "item", "get", "--account="+e.account, "--vault="+vault, "--format=json", "--", item)
}

// run executes op with args. names are strings chosen by the caller that op
// may echo in its diagnostics; they are ignored when classifying errors.
func (e *Exec) run(ctx context.Context, names []string, args ...string) ([]byte, error) {
	if err := e.acquire(ctx); err != nil {
		return nil, err
	}
	defer func() { <-e.sem }()

	cmdCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, e.path, args...)
	cmd.Env = e.env
	stdout := &cappedBuffer{max: MaxStdout}
	stderr := &cappedBuffer{max: MaxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second

	err := cmd.Run()
	if cmdCtx.Err() != nil {
		// Deadline exceeded, or the client went away.
		return nil, &Error{Code: api.CodeTimeout}
	}
	if err != nil {
		return nil, &Error{Code: Classify(stderr.String(), names...)}
	}
	if stdout.overflow {
		return nil, &Error{Code: api.CodeOpFailed}
	}
	return stdout.Bytes(), nil
}

func (e *Exec) acquire(ctx context.Context) error {
	if e.waiting.Add(1) > MaxWaiting {
		e.waiting.Add(-1)
		return &Error{Code: api.CodeBusy}
	}
	defer e.waiting.Add(-1)
	select {
	case e.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return &Error{Code: api.CodeTimeout}
	}
}

// quoted matches the quoted names op puts in its diagnostics.
var quoted = regexp.MustCompile(`"[^"\n]*"|'[^'\n]*'`)

// Classify maps op diagnostics to an error code. The diagnostics themselves
// are never returned to callers or logged.
//
// op echoes vault, item and field names in its messages, and those are chosen
// by the caller: names and quoted spans are removed before matching so that,
// e.g., an item called "Door is locked" cannot change the classification.
func Classify(stderr string, names ...string) api.Code {
	names = slices.Clone(names)
	slices.SortFunc(names, func(a, b string) int { return len(b) - len(a) })
	for _, n := range names {
		if n != "" {
			stderr = strings.ReplaceAll(stderr, n, "")
		}
	}
	s := strings.ToLower(quoted.ReplaceAllString(stderr, ""))
	switch {
	case containsAny(s,
		"authorization prompt dismissed",
		"authorization timeout",
		"not currently signed in",
		"account is not signed in",
		"couldn't connect to the 1password desktop app"):
		return api.CodeOpLocked
	case containsAny(s,
		"isn't a vault",
		"isn't an item",
		"isn't a field",
		"isn't a section",
		"does not have a field",
		"does not have a section",
		"could not find",
		"no item found"):
		return api.CodeNotFound
	default:
		return api.CodeOpFailed
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// cappedBuffer stores at most max bytes and records whether more was written.
// It deliberately does not embed bytes.Buffer: io.Copy would use its ReadFrom
// method and bypass the cap.
type cappedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); len(p) > room {
		b.overflow = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *cappedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *cappedBuffer) String() string { return b.buf.String() }
