// Command opbd is the 1password-broker server. It joins the tailnet as its
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

	"github.com/sylr/1password-broker/internal/config"
	"github.com/sylr/1password-broker/internal/opcli"
	"github.com/sylr/1password-broker/internal/policy"
	"github.com/sylr/1password-broker/internal/server"
)

func main() {
	configPath := flag.String("config", config.DefaultPath(), "configuration file")
	verbose := flag.Bool("verbose", false, "log tsnet internals")
	flag.Parse()

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
		UserLogf: func(format string, args ...any) {
			logger.Info(fmt.Sprintf(format, args...), slog.String("component", "tsnet"))
		},
		Logf: func(string, ...any) {},
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
		Runner:         opcli.NewExec(cfg.Op.Path, cfg.Op.Account, cfg.Op.Timeout),
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
	// Other configuration changes require a restart.
	go func() {
		for range hup {
			if err := out.Reopen(); err != nil {
				logger.Error("reopening log", slog.String("error", err.Error()))
			}
			_, newPol, err := config.Load(configPath)
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
	logger.Info("listening", slog.Any("hosts", hosts), slog.String("addr", cfg.Listen), slog.String("account", cfg.Op.Account))

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
