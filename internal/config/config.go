// Package config loads the opbd configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sylr/1password-broker/internal/policy"
)

// Config is the opbd configuration.
type Config struct {
	// Hostname is the tailnet node name of the broker.
	Hostname string `yaml:"hostname"`
	// StateDir holds the tsnet node state (keys). Created with mode 0700.
	StateDir string `yaml:"state_dir"`
	// Listen is the address the broker listens on inside the tailnet.
	Listen string `yaml:"listen"`
	// LogFile receives the audit log. Empty means stderr.
	LogFile string `yaml:"log_file"`
	// RequestTimeout bounds the handling of a request, queue time included.
	RequestTimeout time.Duration `yaml:"request_timeout"`
	Op             Op            `yaml:"op"`
	Rules          []policy.Rule `yaml:"rules"`
}

// Op configures the 1Password CLI.
type Op struct {
	Path string `yaml:"path"`
	// Account is the UUID of the 1Password account to read from (see
	// `op account list`). It is required so that a change of the default
	// account can never change what a grant refers to.
	Account string `yaml:"account"`
	// Timeout bounds a single op invocation.
	Timeout time.Duration `yaml:"timeout"`
}

var accountUUID = regexp.MustCompile(`^[A-Z0-9]{26}$`)

// MaxRequestTimeout keeps the server deadline below the client timeout, so
// that clients receive the server's error instead of giving up first.
const MaxRequestTimeout = 140 * time.Second

// maxConfigBytes bounds the size of the configuration file.
const maxConfigBytes = 1 << 20

// readPrivate reads the configuration (which defines who may read which
// secrets) after verifying that only the current user can change it: the
// file must be a regular file (not a symlink) owned by the user with mode
// 0600 or stricter, in a directory owned by the user and not writable by
// others. The checks are made on the very file descriptors the content is
// read through, so swapping the file or an ancestor directory between check
// and read has no effect.
func readPrivate(path string) ([]byte, error) {
	dirPath, name := filepath.Split(path)
	if dirPath == "" {
		dirPath = "."
	}
	root, err := os.OpenRoot(dirPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	di, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	if err := checkOwner(dirPath, di); err != nil {
		return nil, err
	}
	if di.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s is writable by group or others (mode %v); chmod 700 it", dirPath, di.Mode().Perm())
	}

	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s must be a regular file, not a symlink", path)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	if err := checkOwner(path, fi); err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by group or others (mode %v); chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigBytes {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return b, nil
}

func checkOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by the current user", path)
	}
	return nil
}

// DefaultPath returns the default configuration file location.
func DefaultPath() string {
	return "~/Library/Application Support/op-broker/config.yaml"
}

// Load reads, validates and compiles the configuration at path.
func Load(path string) (*Config, *policy.Policy, error) {
	path, err := ExpandHome(path)
	if err != nil {
		return nil, nil, err
	}
	b, err := readPrivate(path)
	if err != nil {
		return nil, nil, err
	}
	return Parse(b)
}

// Parse parses and validates a configuration document.
func Parse(b []byte) (*Config, *policy.Policy, error) {
	cfg := &Config{
		Hostname:       "op-broker",
		StateDir:       "~/Library/Application Support/op-broker/tsnet",
		Listen:         ":80",
		RequestTimeout: 120 * time.Second,
		Op: Op{
			Path:    "/opt/homebrew/bin/op",
			Timeout: 60 * time.Second,
		},
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, nil, fmt.Errorf("parsing config: %w", err)
	}
	// A second document would be silently ignored, e.g. rules appended
	// after "---" that the operator believes are in effect.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("parsing config: only one YAML document is allowed")
	}

	var err error
	if cfg.StateDir, err = ExpandHome(cfg.StateDir); err != nil {
		return nil, nil, err
	}
	if cfg.LogFile, err = ExpandHome(cfg.LogFile); err != nil {
		return nil, nil, err
	}
	if cfg.Op.Path, err = ExpandHome(cfg.Op.Path); err != nil {
		return nil, nil, err
	}

	switch {
	case cfg.Hostname == "":
		return nil, nil, errors.New("hostname is required")
	case !accountUUID.MatchString(cfg.Op.Account):
		return nil, nil, errors.New("op.account must be an account UUID (see `op account list`)")
	case !filepath.IsAbs(cfg.Op.Path):
		return nil, nil, errors.New("op.path must be an absolute path")
	case cfg.Op.Timeout <= 0:
		return nil, nil, errors.New("op.timeout must be positive")
	case cfg.RequestTimeout < cfg.Op.Timeout:
		return nil, nil, errors.New("request_timeout must be at least op.timeout")
	case cfg.RequestTimeout > MaxRequestTimeout:
		return nil, nil, fmt.Errorf("request_timeout must be at most %s (clients give up after 150s)", MaxRequestTimeout)
	}

	pol, err := policy.Compile(cfg.Rules)
	if err != nil {
		return nil, nil, err
	}
	return cfg, pol, nil
}

// ExpandHome expands a leading "~/" to the user's home directory.
func ExpandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
}
