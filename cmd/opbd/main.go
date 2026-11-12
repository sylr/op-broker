// Command opbd is the op-broker server. It joins the tailnet as its
// own node, identifies callers with Tailscale WhoIs, authorizes them against
// its configuration and resolves secrets with the local 1Password CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"

	"github.com/sylr/op-broker/internal/config"
	"github.com/sylr/op-broker/internal/opcli"
	"github.com/sylr/op-broker/internal/policy"
	"github.com/sylr/op-broker/internal/server"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		if err := agentMain(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "opbd agent:", err)
			os.Exit(1)
		}
		return
	}

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n  opbd [flags]\n  opbd agent install|uninstall [flags]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	configPath := flag.String("config", config.DefaultPath(), "configuration file")
	verbose := flag.Bool("verbose", false, "log tsnet internals")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("opbd %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	if err := run(*configPath, *verbose); err != nil {
		fmt.Fprintln(os.Stderr, "opbd:", err)
		os.Exit(1)
	}
}

func run(configPath string, verbose bool) error {
	cfg, pol, err := config.Load(configPath)
	if err != nil {
		return err
	}

	out, err := openLog(cfg.LogFile)
	if err != nil {
		return err
	}
	defer out.Close()
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: level}))

	// Register SIGHUP before anything that can block (first tsnet login), so
	// that a reload or log rotation signal never kills the process.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return err
	}

	ts := &tsnet.Server{
		Hostname: cfg.Hostname,
		Dir:      cfg.StateDir,
		// UserLogf prints the login URL when no TS_AUTHKEY is set.
		UserLogf: userLogf(logger, os.Stderr, cfg.LogFile != ""),
		Logf:     func(string, ...any) {},
	}
	if verbose {
		ts.Logf = func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...), slog.String("component", "tsnet"))
		}
	}
	defer ts.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	status, err := ts.Up(ctx)
	if err != nil {
		return fmt.Errorf("starting tsnet: %w", err)
	}
	lc, err := ts.LocalClient()
	if err != nil {
		return err
	}
	ln, err := ts.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}

	hosts := []string{cfg.Hostname}
	if status.Self != nil {
		dnsName := strings.TrimSuffix(status.Self.DNSName, ".")
		hosts = append(hosts, dnsName)
		if status.Self.Tags != nil && status.Self.Tags.Len() > 0 {
			logger.Warn("this node is tagged; clients expect the broker to be an untagged node of its owner unless they set OPB_BROKER",
				slog.Any("tags", status.Self.Tags.AsSlice()))
		}
		if !strings.HasPrefix(dnsName, cfg.Hostname+".") {
			logger.Warn("tailnet name differs from the configured hostname (name collision?); clients must use the actual name",
				slog.String("hostname", cfg.Hostname), slog.String("dns_name", dnsName))
		}
	}
	for _, ip := range status.TailscaleIPs {
		hosts = append(hosts, ip.String())
	}

	srv := server.New(server.Config{
		WhoIs:          tsWhoIs{lc},
		Policy:         pol,
		Runner:         opcli.NewExec(cfg.Op.Path, cfg.Op.Timeout),
		Accounts:       cfg.Op.Accounts,
		DefaultAccount: cfg.Op.DefaultAccount,
		Logger:         logger,
		Hosts:          hosts,
		RequestTimeout: cfg.RequestTimeout,
	})
	// Cancelled when shutdown gives up, so in-flight op calls are killed.
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	httpSrv := &http.Server{
		Handler:           srv,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cfg.RequestTimeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	// SIGHUP reloads the rules and reopens the log file (for rotation).
	// Other configuration changes, accounts included, require a restart.
	go func() {
		for range hup {
			if err := out.Reopen(); err != nil {
				logger.Error("reopening log", slog.String("error", err.Error()))
			}
			newPol, err := reloadPolicy(configPath, cfg.Op)
			if err != nil {
				logger.Error("reloading config, keeping previous rules", slog.String("error", err.Error()))
				continue
			}
			srv.SetPolicy(newPol)
			logger.Info("config reloaded")
		}
	}()

	errc := make(chan error, 1)
	go func() { errc <- httpSrv.Serve(ln) }()
	logger.Info("listening", slog.String("version", version), slog.Any("hosts", hosts), slog.String("addr", cfg.Listen),
		slog.Any("accounts", cfg.Op.Accounts), slog.String("default_account", cfg.Op.DefaultAccount))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		cancelBase()
		httpSrv.Close()
		return err
	}
	return nil
}

// reloadPolicy loads the rules of the configuration at path. They are
// compiled against the accounts of that file, which must therefore be those
// running: accounts only change on restart.
func reloadPolicy(path string, running config.Op) (*policy.Policy, error) {
	cfg, pol, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if !maps.Equal(cfg.Op.Accounts, running.Accounts) || cfg.Op.DefaultAccount != running.DefaultAccount {
		return nil, errors.New("op accounts changed: restart opbd to apply them")
	}
	return pol, nil
}

// userLogf returns the tsnet UserLogf. Its messages, including the login
// URL of the first start, go to the audit log and, when that log is a file,
// to stderr too: the operator running opbd by hand must see them.
func userLogf(logger *slog.Logger, stderr io.Writer, toStderr bool) func(string, ...any) {
	return func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		logger.Info(msg, slog.String("component", "tsnet"))
		if toStderr {
			fmt.Fprintln(stderr, "opbd:", msg)
		}
	}
}

// tsWhoIs adapts the tsnet local client to server.WhoIser.
type tsWhoIs struct {
	lc *local.Client
}

func (w tsWhoIs) WhoIs(ctx context.Context, remoteAddr string) (policy.Identity, error) {
	res, err := w.lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return policy.Identity{}, err
	}
	if res.Node == nil {
		return policy.Identity{}, errors.New("whois: no node")
	}
	id := policy.Identity{
		StableID: string(res.Node.StableID),
		NodeName: res.Node.ComputedName,
		Tags:     res.Node.Tags,
	}
	if res.UserProfile != nil {
		id.LoginName = res.UserProfile.LoginName
	}
	return id, nil
}

// logFile is an audit log destination that can be reopened after rotation.
type logFile struct {
	mu   sync.Mutex
	path string
	w    io.WriteCloser
}

func openLog(path string) (*logFile, error) {
	l := &logFile{path: path}
	if path == "" {
		l.w = nopCloser{os.Stderr}
		return l, nil
	}
	return l, l.Reopen()
}

func (l *logFile) Reopen() error {
	if l.path == "" {
		return nil
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w != nil {
		l.w.Close()
	}
	l.w = f
	return nil
}

func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (l *logFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Close()
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
