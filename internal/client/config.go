package client

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sylr/op-broker/internal/api"
	"github.com/sylr/op-broker/internal/ref"
)

// Config is the opb configuration file.
type Config struct {
	// CurrentContext is used when neither --context nor OPB_CONTEXT is set
	// and no bundle in use pins a context.
	CurrentContext string             `yaml:"current_context"`
	Contexts       map[string]Context `yaml:"contexts"`
	Bundles        map[string]Bundle  `yaml:"bundles"`
}

// Context describes how to reach one broker.
type Context struct {
	Server          string `yaml:"server"`
	Broker          string `yaml:"broker"`
	AllowNonTailnet bool   `yaml:"allow_non_tailnet"`
	// Account is the alias, on this broker, of the account to read from
	// when --account and OPB_ACCOUNT are not set. Empty means the broker's
	// default account.
	Account string `yaml:"account"`
}

// Bundle is a named set of environment variables to populate with secrets.
type Bundle struct {
	// Context, if set, is the context the bundle's references resolve on.
	Context string `yaml:"context"`
	// Account, if set, is the alias of the account the bundle's references
	// resolve in.
	Account string        `yaml:"account"`
	Env     []BundleEntry `yaml:"env"`
}

// Pin holds the settings required by the bundles in use. Empty fields
// require nothing.
type Pin struct {
	Context string
	Account string
}

// BundleEntry populates the environment variable Name with the secret Ref.
type BundleEntry struct {
	Name string `yaml:"name"`
	Ref  string `yaml:"ref"`
}

// maxConfigBytes bounds the size of the configuration file.
const maxConfigBytes = 1 << 20

var configName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// DefaultConfigPath returns $XDG_CONFIG_HOME/op-broker/opb.yaml, or
// ~/.config/op-broker/opb.yaml.
func DefaultConfigPath() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(dir) {
		return filepath.Join(dir, "op-broker", "opb.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "op-broker", "opb.yaml"), nil
}

// LoadConfig reads and validates the configuration at path. A missing file
// yields an empty configuration unless mustExist is set.
func LoadConfig(path string, mustExist bool) (*Config, error) {
	b, err := readConfig(path)
	if errors.Is(err, fs.ErrNotExist) && !mustExist {
		// A dangling symlink is a broken setup, not a missing file.
		if _, lerr := os.Lstat(path); lerr == nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// readConfig reads the configuration after checking that no other user can
// change it: it decides which broker receives requests and which secrets
// are put in the environment. Symlinks are followed, so that files managed
// by dotfile tools (or in the Nix store) work, but no directory along the
// way may let others redirect them (see checkConfigPath).
func readConfig(path string) ([]byte, error) {
	if err := checkConfigPath(path); err != nil {
		return nil, err
	}
	// Opening a FIFO would block: refuse anything but a regular file first.
	// The check on the open file below is the authoritative one.
	if fi, err := os.Stat(path); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
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
	if err := checkConfigFile(path, fi); err != nil {
		return nil, err
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

// ParseConfig parses and validates a configuration document.
func ParseConfig(b []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	var extra any
	switch err := dec.Decode(&extra); {
	case err == nil:
		return nil, errors.New("parsing config: only one YAML document is allowed")
	case !errors.Is(err, io.EOF):
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	for name, c := range cfg.Contexts {
		if !configName.MatchString(name) {
			return nil, fmt.Errorf("invalid context name %q", name)
		}
		// broker and allow_non_tailnet describe the context's server: they
		// must never apply to the default server instead.
		if c.Server == "" {
			return nil, fmt.Errorf("context %q: server is required", name)
		}
		if c.Broker != "" {
			if _, err := parseBroker(c.Broker); err != nil {
				return nil, fmt.Errorf("context %q: %w", name, err)
			}
		}
		if c.Account != "" && !api.ValidAccount(c.Account) {
			return nil, fmt.Errorf("context %q: invalid account %q", name, c.Account)
		}
	}
	if cfg.CurrentContext != "" {
		if _, ok := cfg.Contexts[cfg.CurrentContext]; !ok {
			return nil, fmt.Errorf("current_context: unknown context %q", cfg.CurrentContext)
		}
	}
	for name, b := range cfg.Bundles {
		if !configName.MatchString(name) {
			return nil, fmt.Errorf("invalid bundle name %q", name)
		}
		if err := b.validate(cfg); err != nil {
			return nil, fmt.Errorf("bundle %q: %w", name, err)
		}
	}
	return cfg, nil
}

func (b Bundle) validate(cfg *Config) error {
	if b.Context != "" {
		if _, ok := cfg.Contexts[b.Context]; !ok {
			return fmt.Errorf("unknown context %q", b.Context)
		}
	}
	if b.Account != "" && !api.ValidAccount(b.Account) {
		return fmt.Errorf("invalid account %q", b.Account)
	}
	if len(b.Env) == 0 {
		return errors.New("env is empty")
	}
	var seen []string
	for _, e := range b.Env {
		if !validName(e.Name) {
			return fmt.Errorf("invalid environment variable name %q", e.Name)
		}
		if slices.Contains(seen, e.Name) {
			return fmt.Errorf("%s is set twice", e.Name)
		}
		seen = append(seen, e.Name)
		if _, err := ref.Parse(e.Ref); err != nil {
			return fmt.Errorf("%s: %w", e.Name, err)
		}
	}
	return nil
}

// SelectContext returns the name and settings of the context to use, or ""
// if there is none. pin is the context required by the bundles in use;
// it takes precedence over OPB_CONTEXT and current_context, but conflicts
// with a different --context.
func (c *Config) SelectContext(flagName, envName, pin string) (string, Context, error) {
	name := c.CurrentContext
	switch {
	case pin != "":
		if flagName != "" && flagName != pin {
			return "", Context{}, fmt.Errorf("the bundles in use require context %q, not --context %q", pin, flagName)
		}
		name = pin
	case flagName != "":
		name = flagName
	case envName != "":
		name = envName
	}
	if name == "" {
		return "", Context{}, nil
	}
	ctx, ok := c.Contexts[name]
	if !ok {
		return "", Context{}, fmt.Errorf("unknown context %q", name)
	}
	return name, ctx, nil
}

// BundleEnv returns the variables of the named bundles, in order, with the
// references as values, and the context and account they pin, if any.
// Bundles pinned to different contexts or accounts cannot be combined, since
// one command talks to a single broker and reads from a single account.
func (c *Config) BundleEnv(names []string) (vars []EnvVar, pin Pin, err error) {
	for _, name := range names {
		b, ok := c.Bundles[name]
		if !ok {
			return nil, Pin{}, fmt.Errorf("unknown bundle %q", name)
		}
		if b.Context != "" {
			if pin.Context != "" && pin.Context != b.Context {
				return nil, Pin{}, fmt.Errorf("bundle %q uses context %q but another bundle uses %q", name, b.Context, pin.Context)
			}
			pin.Context = b.Context
		}
		if b.Account != "" {
			if pin.Account != "" && pin.Account != b.Account {
				return nil, Pin{}, fmt.Errorf("bundle %q uses account %q but another bundle uses %q", name, b.Account, pin.Account)
			}
			pin.Account = b.Account
		}
		for _, e := range b.Env {
			vars = append(vars, EnvVar{Key: e.Name, Value: e.Ref})
		}
	}
	return vars, pin, nil
}

// SetCurrentContext sets current_context in the configuration at path to
// name. Only that line is rewritten (or appended), so comments and
// formatting are kept.
func SetCurrentContext(path, name string) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink, probably managed by another tool: change current_context there, or use --context or OPB_CONTEXT", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	b, err := readConfig(path)
	if err != nil {
		return err
	}
	out, err := setCurrentContext(b, name)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if _, err := ParseConfig(out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return writeFileAtomic(path, out, fi.Mode().Perm()&^0o022)
}

func setCurrentContext(b []byte, name string) ([]byte, error) {
	// yaml.v3 counts lone CRs and Unicode separators as line breaks, so its
	// line numbers would not match the lines edited below.
	if strings.ContainsAny(string(b), "\u0085\u2028\u2029") || strings.Count(string(b), "\r") != strings.Count(string(b), "\r\n") {
		return nil, errors.New("cannot edit current_context: the file uses unusual line breaks; edit it by hand")
	}
	cfg, err := ParseConfig(b)
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Contexts[name]; !ok {
		return nil, fmt.Errorf("unknown context %q", name)
	}
	// Context names never need escaping, but quoting keeps names such as
	// "true" or "1.0" strings.
	line := "current_context: " + strconv.Quote(name)

	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return append([]byte(line+"\n"), b...), nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || root.Style&yaml.FlowStyle != 0 || root.Column != 1 {
		return nil, errors.New("cannot edit current_context: the top level is not an unindented block mapping; edit the file by hand")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		if k.Value != "current_context" {
			continue
		}
		if v.Kind != yaml.ScalarNode || v.Line != k.Line || v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
			return nil, errors.New("cannot edit current_context: it is not a single-line value; edit the file by hand")
		}
		if comment := cmp.Or(v.LineComment, k.LineComment); comment != "" {
			line += " " + comment
		}
		lines := strings.SplitAfter(string(b), "\n")
		if k.Line > len(lines) || k.Column != 1 || !strings.HasPrefix(lines[k.Line-1], "current_context:") {
			return nil, errors.New("cannot edit current_context: unexpected layout; edit the file by hand")
		}
		old := lines[k.Line-1]
		eol := old[len(strings.TrimRight(old, "\r\n")):]
		lines[k.Line-1] = line + eol
		return []byte(strings.Join(lines, "")), nil
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	return append(b, line+"\n"...), nil
}
