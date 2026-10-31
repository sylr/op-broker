// Command opb is the op-broker client. It resolves 1Password secret
// references through an opbd server on the tailnet, with a subset of the op
// CLI interface.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"

	"github.com/sylr/op-broker/internal/api"
	"github.com/sylr/op-broker/internal/client"
)

const usage = `usage: opb [global flags] <command> [flags]

Commands:
  read [-n] <op://vault/item/[section/]field>
  inject [-i template] [-o output]
  run [--env-file file]... [--bundle name]... -- <command> [args...]
  env <bundle>...
  item get <item> --vault <vault> [--format json]
  context list | show [name] | use <name>
  version

Global flags:
  --config file        configuration file ($OPB_CONFIG, default
                       $XDG_CONFIG_HOME/op-broker/opb.yaml or ~/.config/op-broker/opb.yaml)
  --context name       context to use ($OPB_CONTEXT, default current_context)
  --server URL         broker URL ($OPB_SERVER, default from the context, then ` + client.DefaultServer + `)
  --broker identity    expected tailnet identity of the broker ($OPB_BROKER)
  --allow-non-tailnet  INSECURE, for testing ($OPB_ALLOW_NON_TAILNET=1 or 0)

Flags override environment variables, which override the context. A context's
broker and allow_non_tailnet only apply to its own server: once --server or
OPB_SERVER is set, they are not used. A bundle pinned to a context always uses
that context: OPB_SERVER, OPB_BROKER and OPB_ALLOW_NON_TAILNET are ignored,
and --server, --broker, --allow-non-tailnet or another --context are errors.

Before sending anything, the client asks the local Tailscale daemon who owns
the server address and requires it to be the expected broker identity:
user:<login> (an untagged node of that user), tag:<name> or node:<stable-id>.
By default the server must be an untagged node owned by the same user as this
machine; tagged machines must set one. --allow-non-tailnet disables this
check and the tailnet address restriction; use it only for testing.

Exit status: 0 success, 1 error, 2 access denied, 3 1Password locked,
approval pending or not given in time on the server.
`

const (
	exitOK = iota
	exitError
	exitDenied
	exitLocked
)

// maxTemplateBytes bounds the size of an inject template.
const maxTemplateBytes = 16 << 20

// Set at build time with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// globals holds the global flags and the configuration file.
type globals struct {
	configPath      string
	context         string
	server          string
	broker          string
	allowNonTailnet bool

	set    map[string]bool // global flags given on the command line
	getenv func(string) string
	cfg    *client.Config
}

// settings are the effective connection settings of a command.
type settings struct {
	context         string // "" when no context is in use
	server          string
	broker          string // "" for the default identity
	allowNonTailnet bool
}

func run(args []string) int {
	g := &globals{getenv: os.Getenv}
	global := flag.NewFlagSet("opb", flag.ContinueOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	global.StringVar(&g.configPath, "config", "", "configuration file")
	global.StringVar(&g.context, "context", "", "context to use")
	global.StringVar(&g.server, "server", "", "opbd server URL")
	global.StringVar(&g.broker, "broker", "", "expected tailnet identity of the server: user:<login>, tag:<name> or node:<stable-id> (default: untagged node of this machine's owner)")
	global.BoolVar(&g.allowNonTailnet, "allow-non-tailnet", false, "INSECURE, for testing: connect to any address and skip broker verification")
	if err := global.Parse(args); err != nil {
		return usageExit(err)
	}
	g.set = map[string]bool{}
	global.Visit(func(f *flag.Flag) { g.set[f.Name] = true })
	args = global.Args()
	if len(args) == 0 {
		global.Usage()
		return exitError
	}
	switch args[0] {
	case "version", "--version", "-version":
		fmt.Printf("opb %s (commit %s, built %s)\n", version, commit, date)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, usage)
		return exitOK
	}
	if err := g.loadConfig(); err != nil {
		return fail(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	cmd, args := args[0], args[1:]
	switch cmd {
	case "read":
		err = cmdRead(ctx, g, args)
	case "inject":
		err = cmdInject(ctx, g, args)
	case "run":
		err = cmdRun(ctx, g, args)
	case "env":
		err = cmdEnv(ctx, g, args)
	case "item":
		err = cmdItem(ctx, g, args)
	case "context":
		err = cmdContext(g, args)
	default:
		fmt.Fprintf(os.Stderr, "opb: unknown command %q\n\n%s", cmd, usage)
		return exitError
	}
	if err != nil {
		return fail(err)
	}
	return exitOK
}

// loadConfig loads --config, $OPB_CONFIG or the default configuration file.
// Only the default file may be missing.
func (g *globals) loadConfig() error {
	explicit := true
	g.configPath = cmp.Or(g.configPath, g.getenv("OPB_CONFIG"))
	if g.configPath == "" {
		explicit = false
		var err error
		if g.configPath, err = client.DefaultConfigPath(); err != nil {
			g.cfg = &client.Config{}
			return nil
		}
	}
	var err error
	g.cfg, err = client.LoadConfig(g.configPath, explicit)
	return err
}

// settings resolves the connection settings. pin is the context required by
// the bundles in use, if any.
//
// A context's settings go together: its broker identity and
// allow_non_tailnet describe its server, so they are dropped when the server
// comes from elsewhere. Otherwise an insecure test context would disable
// verification of a server given with --server.
func (g *globals) settings(pin string) (settings, error) {
	name, c, err := g.cfg.SelectContext(g.context, g.getenv("OPB_CONTEXT"), pin)
	if err != nil {
		return settings{}, err
	}
	if pin != "" {
		// The bundles' references belong to this broker: leftover
		// environment overrides must not redirect them.
		for _, f := range []string{"server", "broker", "allow-non-tailnet"} {
			if g.set[f] {
				return settings{}, fmt.Errorf("--%s cannot be used with bundles pinned to context %q", f, pin)
			}
		}
		return settings{
			context:         name,
			server:          c.Server,
			broker:          c.Broker,
			allowNonTailnet: c.AllowNonTailnet,
		}, nil
	}

	s := settings{context: name}
	fromContext := false
	switch {
	case g.set["server"]:
		s.server = g.server
	case g.getenv("OPB_SERVER") != "":
		s.server = g.getenv("OPB_SERVER")
	case c.Server != "":
		s.server, fromContext = c.Server, true
	default:
		s.server = client.DefaultServer
	}
	switch {
	case g.set["broker"]:
		s.broker = g.broker
	case g.getenv("OPB_BROKER") != "":
		s.broker = g.getenv("OPB_BROKER")
	case fromContext:
		s.broker = c.Broker
	}
	switch {
	case g.set["allow-non-tailnet"]:
		s.allowNonTailnet = g.allowNonTailnet
	case g.getenv("OPB_ALLOW_NON_TAILNET") != "":
		// Either way: OPB_ALLOW_NON_TAILNET=0 must override an insecure
		// context.
		v, err := strconv.ParseBool(g.getenv("OPB_ALLOW_NON_TAILNET"))
		if err != nil {
			return settings{}, fmt.Errorf("invalid OPB_ALLOW_NON_TAILNET %q: want 1 or 0", g.getenv("OPB_ALLOW_NON_TAILNET"))
		}
		s.allowNonTailnet = v
	case fromContext:
		s.allowNonTailnet = c.AllowNonTailnet
	}
	return s, nil
}

// connect returns a client for the broker selected by the settings.
func (g *globals) connect(pin string) (*client.Client, error) {
	s, err := g.settings(pin)
	if err != nil {
		return nil, err
	}
	opts := client.Options{AllowNonTailnet: s.allowNonTailnet}
	if !s.allowNonTailnet {
		if opts.Verify, err = client.TailscaleVerifier(s.broker); err != nil {
			return nil, err
		}
	}
	return client.New(s.server, opts)
}

func cmdRead(ctx context.Context, g *globals, args []string) error {
	fs := newFlagSet("read", "read [-n] <op://vault/item/[section/]field>")
	noNewline := fs.Bool("n", false, "do not print a trailing newline")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(fs)
	}
	c, err := g.connect("")
	if err != nil {
		return err
	}
	values, err := c.Resolve(ctx, pos)
	if err != nil {
		return err
	}
	out := values[pos[0]]
	if !*noNewline {
		out += "\n"
	}
	_, err = io.WriteString(os.Stdout, out)
	return err
}

func cmdInject(ctx context.Context, g *globals, args []string) error {
	fs := newFlagSet("inject", "inject [-i template] [-o output]\n\n"+
		"Supported template syntax: {{ op://vault/item/field }}, where the reference\n"+
		"may use $VAR or ${VAR}. Other op inject syntax is rejected.")
	in := fs.String("i", "", "template file (default: stdin)")
	out := fs.String("o", "", "output file, written with mode 0600 (default: stdout)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageError(fs)
	}

	r := io.Reader(os.Stdin)
	if *in != "" {
		f, err := os.Open(*in)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	src, err := io.ReadAll(io.LimitReader(r, maxTemplateBytes+1))
	if err != nil {
		return err
	}
	if len(src) > maxTemplateBytes {
		return errors.New("template too large")
	}

	tpl, err := client.ParseTemplate(string(src), os.LookupEnv)
	if err != nil {
		return err
	}
	c, err := g.connect("")
	if err != nil {
		return err
	}
	values, err := resolveAll(ctx, c, tpl.Refs())
	if err != nil {
		return err
	}
	rendered, err := tpl.Render(values)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(rendered)
		return err
	}
	return client.WriteFileAtomic(*out, rendered)
}

func cmdRun(ctx context.Context, g *globals, args []string) error {
	fs := newFlagSet("run", "run [--env-file file]... [--bundle name]... -- <command> [args...]\n\n"+
		"Environment variables whose whole value is an op:// reference are resolved\n"+
		"before <command> is executed. As with op run, env files override the process\n"+
		"environment, and later env files override earlier ones. Bundles from the\n"+
		"configuration file override env files, and later bundles override earlier\n"+
		"ones.\n\n"+
		"WARNING: unlike op run, the output of <command> is NOT masked: secrets it\n"+
		"prints will appear in clear.")
	var envFiles stringsFlag
	fs.Var(&envFiles, "env-file", "dotenv file to load (repeatable)")
	var bundles stringsFlag
	fs.Var(&bundles, "bundle", "bundle from the configuration file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return usageError(fs)
	}

	var files [][]client.EnvVar
	for _, path := range envFiles {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		vars, err := client.ParseDotenv(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		files = append(files, vars)
	}
	bundleVars, pin, err := g.cfg.BundleEnv(bundles)
	if err != nil {
		return err
	}
	c, err := g.connect(pin)
	if err != nil {
		return err
	}
	env := client.MergeEnv(os.Environ(), append(files, bundleVars)...)
	values, err := resolveAll(ctx, c, client.EnvRefs(env))
	if err != nil {
		return err
	}
	if env, err = client.SubstituteEnv(env, values); err != nil {
		return err
	}
	return client.Exec(argv, env)
}

func cmdEnv(ctx context.Context, g *globals, args []string) error {
	fs := newFlagSet("env", "env <bundle>...\n\n"+
		"Prints POSIX shell export statements for the variables of the bundles,\n"+
		"later bundles overriding earlier ones. Use it as:\n\n"+
		"  eval \"$(opb env <bundle>)\"\n\n"+
		"WARNING: the secrets end up in the shell's environment, where every command\n"+
		"it runs can read them. Prefer opb run --bundle when one command needs them.")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return usageError(fs)
	}
	vars, pin, err := g.cfg.BundleEnv(pos)
	if err != nil {
		return err
	}
	c, err := g.connect(pin)
	if err != nil {
		return err
	}
	env := client.MergeEnv(nil, vars)
	values, err := resolveAll(ctx, c, client.EnvRefs(env))
	if err != nil {
		return err
	}
	if env, err = client.SubstituteEnv(env, values); err != nil {
		return err
	}
	var b strings.Builder
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		fmt.Fprintf(&b, "export %s=%s\n", k, shellQuote(v))
	}
	_, err = io.WriteString(os.Stdout, b.String())
	return err
}

// shellQuote quotes s for a POSIX shell. Single quotes keep every byte,
// newlines included, literal.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func cmdItem(ctx context.Context, g *globals, args []string) error {
	fs := newFlagSet("item", "item get <item> --vault <vault> [--format json]")
	vault := fs.String("vault", "", "vault name or ID (required)")
	format := fs.String("format", "json", "output format (only json is supported)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 || pos[0] != "get" || *vault == "" {
		return usageError(fs)
	}
	if *format != "json" {
		return fmt.Errorf("unsupported format %q (only json is supported)", *format)
	}
	c, err := g.connect("")
	if err != nil {
		return err
	}
	body, err := c.Item(ctx, *vault, pos[1])
	if err != nil {
		return err
	}
	if !strings.HasSuffix(string(body), "\n") {
		body = append(body, '\n')
	}
	_, err = os.Stdout.Write(body)
	return err
}

func cmdContext(g *globals, args []string) error {
	fs := newFlagSet("context", "context list | show [name] | use <name>")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return usageError(fs)
	}
	switch {
	case pos[0] == "list" && len(pos) == 1:
		// An unknown --context or OPB_CONTEXT must not prevent listing the
		// valid names: nothing is marked active then.
		active, _, _ := g.cfg.SelectContext(g.context, g.getenv("OPB_CONTEXT"), "")
		var b strings.Builder
		for _, name := range slices.Sorted(maps.Keys(g.cfg.Contexts)) {
			mark := " "
			if name == active {
				mark = "*"
			}
			fmt.Fprintf(&b, "%s %s\t%s\n", mark, name, g.cfg.Contexts[name].Server)
		}
		_, err := io.WriteString(os.Stdout, b.String())
		return err
	case pos[0] == "show" && len(pos) <= 2:
		if len(pos) == 2 {
			g.context = pos[1]
		}
		s, err := g.settings("")
		if err != nil {
			return err
		}
		fmt.Printf("context: %s\nserver: %s\nbroker: %s\nallow_non_tailnet: %t\n",
			cmp.Or(s.context, "(none)"), s.server, cmp.Or(s.broker, "(untagged node of this machine's owner)"), s.allowNonTailnet)
		return nil
	case pos[0] == "use" && len(pos) == 2:
		if g.configPath == "" {
			return errors.New("no configuration file: set --config or OPB_CONFIG")
		}
		if err := client.SetCurrentContext(g.configPath, pos[1]); err != nil {
			return err
		}
		fmt.Printf("current context set to %q in %s\n", pos[1], g.configPath)
		if override := cmp.Or(g.context, g.getenv("OPB_CONTEXT")); override != "" && override != pos[1] {
			fmt.Fprintf(os.Stderr, "opb: note: --context or OPB_CONTEXT (%q) still takes precedence\n", override)
		}
		return nil
	default:
		return usageError(fs)
	}
}

// resolveAll resolves refs in a single request, so that every ref is
// authorized before any of them is read.
func resolveAll(ctx context.Context, c *client.Client, refs []string) (map[string]string, error) {
	switch {
	case len(refs) == 0:
		return map[string]string{}, nil
	case len(refs) > api.MaxRefs:
		return nil, fmt.Errorf("too many distinct secret references (%d, maximum %d)", len(refs), api.MaxRefs)
	}
	return c.Resolve(ctx, refs)
}

func newFlagSet(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: opb %s\n\nFlags:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseInterspersed parses flags that may appear before, between or after
// positional arguments. Everything after "--" is positional.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

type errUsage struct{}

func (errUsage) Error() string { return "invalid usage" }

func usageError(fs *flag.FlagSet) error {
	fs.Usage()
	return errUsage{}
}

func usageExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	return exitError
}

func fail(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	if _, ok := errors.AsType[errUsage](err); !ok && !strings.HasPrefix(err.Error(), "flag provided but not defined") {
		fmt.Fprintln(os.Stderr, "opb:", err)
	}
	if ce, ok := errors.AsType[*client.Error](err); ok {
		switch ce.Code {
		case api.CodeDenied:
			return exitDenied
		case api.CodeOpLocked, api.CodeTimeout:
			return exitLocked
		}
	}
	return exitError
}
