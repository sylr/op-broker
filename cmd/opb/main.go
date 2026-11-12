// Command opb is the op-broker client. It resolves 1Password secret
// references through an opbd server on the tailnet, with a subset of the op
// CLI interface.
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sylr/op-broker/internal/api"
	"github.com/sylr/op-broker/internal/client"
)

const rootLong = `opb resolves 1Password secret references through an opbd server on the
tailnet, with a subset of the op CLI interface.

The configuration file is --config, then $OPB_CONFIG, then
$XDG_CONFIG_HOME/op-broker/opb.yaml or ~/.config/op-broker/opb.yaml. The
active context is --context, then $OPB_CONTEXT, then current_context.

Flags override environment variables ($OPB_SERVER, $OPB_BROKER,
$OPB_ALLOW_NON_TAILNET=1 or 0), which override the context. A context's
broker and allow_non_tailnet only apply to its own server: once --server or
OPB_SERVER is set, they are not used. A bundle pinned to a context always uses
that context: OPB_SERVER, OPB_BROKER, OPB_ALLOW_NON_TAILNET and OPB_ACCOUNT
are ignored, and --server, --broker, --allow-non-tailnet or another --context
are errors. Without a context or override, the server is ` + client.DefaultServer + `.

The account (an alias defined by the server, which reads from its default
account otherwise) is the one pinned by the bundles in use, then --account,
then $OPB_ACCOUNT, then the context's account. Like its broker, a context's
account only applies to its own server. A bundle pinned to an account always
uses it: another --account is an error. One command reads from one account.

Before sending anything, the client asks the local Tailscale daemon who owns
the server address and requires it to be the expected broker identity:
user:<login> (an untagged node of that user), tag:<name> or node:<stable-id>.
By default the server must be an untagged node owned by the same user as this
machine; tagged machines must set one. --allow-non-tailnet disables this
check and the tailnet address restriction; use it only for testing.

Exit status: 0 success, 1 error, 2 access denied, 3 1Password locked,
approval pending or not given in time on the server.`

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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string) int {
	root := newRootCmd(&globals{getenv: os.Getenv})
	root.SetArgs(args)
	return fail(root.ExecuteContext(ctx))
}

// globals holds the global flags and the configuration file.
type globals struct {
	configPath      string
	context         string
	server          string
	broker          string
	allowNonTailnet bool
	account         string

	flags  *pflag.FlagSet // the global flags, to tell which were given
	getenv func(string) string
	cfg    *client.Config
}

// settings are the effective connection settings of a command.
type settings struct {
	context         string // "" when no context is in use
	server          string
	broker          string // "" for the default identity
	allowNonTailnet bool
	account         string // "" for the server's default account
}

func newRootCmd(g *globals) *cobra.Command {
	root := &cobra.Command{
		Use:     "opb",
		Short:   "Resolve 1Password secret references through op-broker",
		Long:    rootLong,
		Version: fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
		// Errors are printed by fail, which also picks the exit status.
		SilenceErrors: true,
		SilenceUsage:  true,
		// Runnable, so that a missing command is an error rather than a help
		// screen with exit status 0.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return &usageError{cmd, errors.New("missing command")}
		},
	}
	root.SetVersionTemplate("opb {{.Version}}\n")
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return &usageError{cmd, err}
	})

	// Subcommands share these flags (the same *pflag.Flag values), so
	// Changed reports flags given before or after the subcommand.
	pf := root.PersistentFlags()
	g.flags = pf
	pf.StringVar(&g.configPath, "config", "", "configuration file")
	pf.StringVar(&g.context, "context", "", "context to use")
	pf.StringVar(&g.server, "server", "", "opbd server URL")
	pf.StringVar(&g.broker, "broker", "", "expected tailnet identity of the server: user:<login>, tag:<name> or node:<stable-id> (default: untagged node of this machine's owner)")
	pf.BoolVar(&g.allowNonTailnet, "allow-non-tailnet", false, "INSECURE, for testing: connect to any address and skip broker verification")
	pf.StringVar(&g.account, "account", "", "alias of the server-side account to read from (default: the server's default account)")
	_ = root.MarkPersistentFlagFilename("config", "yaml", "yml")
	_ = root.RegisterFlagCompletionFunc("context", g.completeContexts)
	_ = root.RegisterFlagCompletionFunc("server", g.completeServers)
	_ = root.RegisterFlagCompletionFunc("broker", g.completeBrokers)
	_ = root.RegisterFlagCompletionFunc("account", g.completeAccounts)

	root.AddGroup(
		&cobra.Group{ID: "secrets", Title: "Secret commands:"},
		&cobra.Group{ID: "config", Title: "Configuration commands:"},
	)
	for _, cmd := range []*cobra.Command{
		newReadCmd(g), newInjectCmd(g), newRunCmd(g), newEnvCmd(g), newItemCmd(g),
	} {
		cmd.GroupID = "secrets"
		root.AddCommand(cmd)
	}
	ctxCmd := newContextCmd(g)
	ctxCmd.GroupID = "config"
	root.AddCommand(ctxCmd, newVersionCmd())
	return root
}

// config returns the configuration file, loading it on first use, so that
// commands that need none (help, completion, version) work with a broken one.
func (g *globals) config() (*client.Config, error) {
	if g.cfg == nil {
		if err := g.loadConfig(); err != nil {
			return nil, err
		}
	}
	return g.cfg, nil
}

// loadConfig loads --config, $OPB_CONFIG or the default configuration file.
// Only the default file may be missing.
func (g *globals) loadConfig() error {
	explicit := true
	path := cmp.Or(g.configPath, g.getenv("OPB_CONFIG"))
	if path == "" {
		explicit = false
		var err error
		if path, err = client.DefaultConfigPath(); err != nil {
			g.cfg = &client.Config{}
			return nil
		}
	}
	cfg, err := client.LoadConfig(path, explicit)
	if err != nil {
		return err
	}
	g.configPath, g.cfg = path, cfg
	return nil
}

// changed reports whether the global flag name was given.
func (g *globals) changed(name string) bool {
	return g.flags != nil && g.flags.Changed(name)
}

// settings resolves the connection settings. pin holds the context and
// account required by the bundles in use, if any.
//
// A context's settings go together: its broker identity, allow_non_tailnet
// and account describe its server, so they are dropped when the server
// comes from elsewhere. Otherwise an insecure test context would disable
// verification of a server given with --server.
func (g *globals) settings(pin client.Pin) (settings, error) {
	cfg, err := g.config()
	if err != nil {
		return settings{}, err
	}
	name, c, err := cfg.SelectContext(g.context, g.getenv("OPB_CONTEXT"), pin.Context)
	if err != nil {
		return settings{}, err
	}
	if pin.Context != "" {
		// The bundles' references belong to this broker: leftover
		// environment overrides must not redirect them.
		for _, f := range []string{"server", "broker", "allow-non-tailnet"} {
			if g.changed(f) {
				return settings{}, fmt.Errorf("--%s cannot be used with bundles pinned to context %q", f, pin.Context)
			}
		}
		account, err := g.selectAccount(pin, c.Account)
		if err != nil {
			return settings{}, err
		}
		return settings{
			context:         name,
			server:          c.Server,
			broker:          c.Broker,
			allowNonTailnet: c.AllowNonTailnet,
			account:         account,
		}, nil
	}

	s := settings{context: name}
	fromContext := false
	switch {
	case g.changed("server"):
		s.server = g.server
	case g.getenv("OPB_SERVER") != "":
		s.server = g.getenv("OPB_SERVER")
	case c.Server != "":
		s.server, fromContext = c.Server, true
	default:
		s.server = client.DefaultServer
	}
	switch {
	case g.changed("broker"):
		s.broker = g.broker
	case g.getenv("OPB_BROKER") != "":
		s.broker = g.getenv("OPB_BROKER")
	case fromContext:
		s.broker = c.Broker
	}
	switch {
	case g.changed("allow-non-tailnet"):
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
	var contextAccount string
	if fromContext {
		contextAccount = c.Account
	}
	if s.account, err = g.selectAccount(pin, contextAccount); err != nil {
		return settings{}, err
	}
	return s, nil
}

// selectAccount returns the account alias to use: the one pinned by the
// bundles in use, then --account, then OPB_ACCOUNT, then contextAccount.
// Like the other environment overrides, OPB_ACCOUNT is ignored when the
// bundles pin a context.
func (g *globals) selectAccount(pin client.Pin, contextAccount string) (string, error) {
	var account string
	switch {
	case pin.Account != "":
		if g.changed("account") && g.account != pin.Account {
			return "", fmt.Errorf("the bundles in use require account %q, not --account %q", pin.Account, g.account)
		}
		account = pin.Account
	case g.changed("account"):
		account = g.account
	case pin.Context == "" && g.getenv("OPB_ACCOUNT") != "":
		account = g.getenv("OPB_ACCOUNT")
	default:
		account = contextAccount
	}
	if account != "" && !api.ValidAccount(account) {
		return "", fmt.Errorf("invalid account %q", account)
	}
	return account, nil
}

// connect returns a client for the broker and account selected by the
// settings.
func (g *globals) connect(pin client.Pin) (*client.Client, error) {
	s, err := g.settings(pin)
	if err != nil {
		return nil, err
	}
	opts := client.Options{AllowNonTailnet: s.allowNonTailnet, Account: s.account}
	if !s.allowNonTailnet {
		if opts.Verify, err = client.TailscaleVerifier(s.broker); err != nil {
			return nil, err
		}
	}
	return client.New(s.server, opts)
}

func newReadCmd(g *globals) *cobra.Command {
	var noNewline bool
	cmd := &cobra.Command{
		Use:               "read <op://vault/item/[section/]field>",
		Short:             "Print the value of a secret reference",
		Args:              usageArgs(cobra.ExactArgs(1)),
		ValidArgsFunction: g.completeRefs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := g.connect(client.Pin{})
			if err != nil {
				return err
			}
			values, err := c.Resolve(cmd.Context(), args)
			if err != nil {
				return err
			}
			out := values[args[0]]
			if !noNewline {
				out += "\n"
			}
			_, err = io.WriteString(os.Stdout, out)
			return err
		},
	}
	cmd.Flags().BoolVarP(&noNewline, "no-newline", "n", false, "do not print a trailing newline")
	return cmd
}

func newInjectCmd(g *globals) *cobra.Command {
	var in, out string
	cmd := &cobra.Command{
		Use:   "inject [-i template] [-o output]",
		Short: "Render a template with secret references",
		Long: "Renders a template, replacing secret references with their values.\n\n" +
			"Supported template syntax: {{ op://vault/item/field }}, where the reference\n" +
			"may use $VAR or ${VAR}. Other op inject syntax is rejected.",
		Args:              usageArgs(cobra.NoArgs),
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Fail on a broken configuration before waiting on stdin.
			if _, err := g.config(); err != nil {
				return err
			}
			r := io.Reader(os.Stdin)
			if in != "" {
				f, err := os.Open(in)
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
			c, err := g.connect(client.Pin{})
			if err != nil {
				return err
			}
			values, err := resolveAll(cmd.Context(), c, tpl.Refs())
			if err != nil {
				return err
			}
			rendered, err := tpl.Render(values)
			if err != nil {
				return err
			}
			if out == "" {
				_, err = os.Stdout.Write(rendered)
				return err
			}
			return client.WriteFileAtomic(out, rendered)
		},
	}
	cmd.Flags().StringVarP(&in, "in-file", "i", "", "template file (default: stdin)")
	cmd.Flags().StringVarP(&out, "out-file", "o", "", "output file, written with mode 0600 (default: stdout)")
	_ = cmd.MarkFlagFilename("in-file")
	_ = cmd.MarkFlagFilename("out-file")
	return cmd
}

func newRunCmd(g *globals) *cobra.Command {
	var envFiles, bundles []string
	cmd := &cobra.Command{
		Use:   "run [--env-file file]... [--bundle name]... -- <command> [args...]",
		Short: "Run a command with secrets in its environment",
		Long: "Environment variables whose whole value is an op:// reference are resolved\n" +
			"before <command> is executed. As with op run, env files override the process\n" +
			"environment, and later env files override earlier ones. Bundles from the\n" +
			"configuration file override env files, and later bundles override earlier\n" +
			"ones.\n\n" +
			"With bundles pinned to an account, every reference must come from them: a\n" +
			"reference from the environment or an env file is an error, since it would be\n" +
			"read in the bundles' account.\n\n" +
			"WARNING: unlike op run, the output of <command> is NOT masked: secrets it\n" +
			"prints will appear in clear.",
		Args: usageArgs(cobra.MinimumNArgs(1)),
		// The command and its arguments: offer file names.
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveDefault
		},
		RunE: func(cmd *cobra.Command, argv []string) error {
			cfg, err := g.config()
			if err != nil {
				return err
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
			bundleVars, pin, err := cfg.BundleEnv(bundles)
			if err != nil {
				return err
			}
			env := client.MergeEnv(os.Environ(), append(files, bundleVars)...)
			// The account pinned by the bundles is meant for their own
			// references: other references, from the environment or env
			// files, were written for whatever account the command would
			// otherwise use, and the same vault names exist in every account.
			if pin.Account != "" {
				if names := client.ForeignRefs(env, bundleVars); len(names) > 0 {
					return fmt.Errorf("bundles pinned to account %q only resolve their own references, but these variables from the environment or env files are references too: %s",
						pin.Account, strings.Join(names, ", "))
				}
			}
			c, err := g.connect(pin)
			if err != nil {
				return err
			}
			values, err := resolveAll(cmd.Context(), c, client.EnvRefs(env))
			if err != nil {
				return err
			}
			if env, err = client.SubstituteEnv(env, values); err != nil {
				return err
			}
			return client.Exec(argv, env)
		},
	}
	// Flags after <command> belong to it.
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringArrayVar(&envFiles, "env-file", nil, "dotenv file to load (repeatable)")
	cmd.Flags().StringArrayVar(&bundles, "bundle", nil, "bundle from the configuration file (repeatable)")
	_ = cmd.MarkFlagFilename("env-file")
	_ = cmd.RegisterFlagCompletionFunc("bundle", func(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return g.completeBundles(bundles, toComplete)
	})
	return cmd
}

func newEnvCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "env <bundle>...",
		Short: "Print shell exports for bundles",
		Long: "Prints POSIX shell export statements for the variables of the bundles,\n" +
			"later bundles overriding earlier ones. Use it as:\n\n" +
			"  eval \"$(opb env <bundle>)\"\n\n" +
			"WARNING: the secrets end up in the shell's environment, where every command\n" +
			"it runs can read them. Prefer opb run --bundle when one command needs them.",
		Args: usageArgs(cobra.MinimumNArgs(1)),
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			return g.completeBundles(args, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := g.config()
			if err != nil {
				return err
			}
			vars, pin, err := cfg.BundleEnv(args)
			if err != nil {
				return err
			}
			c, err := g.connect(pin)
			if err != nil {
				return err
			}
			env := client.MergeEnv(nil, vars)
			values, err := resolveAll(cmd.Context(), c, client.EnvRefs(env))
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
		},
	}
}

// shellQuote quotes s for a POSIX shell. Single quotes keep every byte,
// newlines included, literal.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func newItemCmd(g *globals) *cobra.Command {
	cmd := newGroupCmd("item", "Get whole items")
	var vault, format string
	get := &cobra.Command{
		Use:   "get <item> --vault <vault>",
		Short: "Print an item as JSON (needs an items grant)",
		Args:  usageArgs(cobra.ExactArgs(1)),
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return g.completeItems(vault, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if vault == "" {
				return &usageError{cmd, errors.New(`required flag "vault" not set`)}
			}
			if format != "json" {
				return fmt.Errorf("unsupported format %q (only json is supported)", format)
			}
			c, err := g.connect(client.Pin{})
			if err != nil {
				return err
			}
			body, err := c.Item(cmd.Context(), vault, args[0])
			if err != nil {
				return err
			}
			if !strings.HasSuffix(string(body), "\n") {
				body = append(body, '\n')
			}
			_, err = os.Stdout.Write(body)
			return err
		},
	}
	get.Flags().StringVar(&vault, "vault", "", "vault name or ID (required)")
	get.Flags().StringVar(&format, "format", "json", "output format (only json is supported)")
	_ = get.RegisterFlagCompletionFunc("vault", g.completeVaults)
	_ = get.RegisterFlagCompletionFunc("format", cobra.FixedCompletions([]cobra.Completion{"json"}, cobra.ShellCompDirectiveNoFileComp))
	cmd.AddCommand(get)
	return cmd
}

func newContextCmd(g *globals) *cobra.Command {
	cmd := newGroupCmd("context", "List, show and switch contexts")
	list := &cobra.Command{
		Use:               "list",
		Aliases:           []string{"ls"},
		Short:             "List contexts; * marks the active one",
		Args:              usageArgs(cobra.NoArgs),
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(*cobra.Command, []string) error {
			cfg, err := g.config()
			if err != nil {
				return err
			}
			// An unknown --context or OPB_CONTEXT must not prevent listing the
			// valid names: nothing is marked active then.
			active, _, _ := cfg.SelectContext(g.context, g.getenv("OPB_CONTEXT"), "")
			var b strings.Builder
			for _, name := range slices.Sorted(maps.Keys(cfg.Contexts)) {
				mark := " "
				if name == active {
					mark = "*"
				}
				fmt.Fprintf(&b, "%s %s\t%s\n", mark, name, cfg.Contexts[name].Server)
			}
			_, err = io.WriteString(os.Stdout, b.String())
			return err
		},
	}
	show := &cobra.Command{
		Use:               "show [name]",
		Short:             "Show the effective server, broker identity and account",
		Args:              usageArgs(cobra.MaximumNArgs(1)),
		ValidArgsFunction: g.completeContextArg,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 {
				g.context = args[0]
			}
			s, err := g.settings(client.Pin{})
			if err != nil {
				return err
			}
			fmt.Printf("context: %s\nserver: %s\nbroker: %s\nallow_non_tailnet: %t\naccount: %s\n",
				cmp.Or(s.context, "(none)"), s.server, cmp.Or(s.broker, "(untagged node of this machine's owner)"), s.allowNonTailnet,
				cmp.Or(s.account, "(server default)"))
			return nil
		},
	}
	use := &cobra.Command{
		Use:               "use <name>",
		Short:             "Set current_context in the configuration file",
		Args:              usageArgs(cobra.ExactArgs(1)),
		ValidArgsFunction: g.completeContextArg,
		RunE: func(_ *cobra.Command, args []string) error {
			if _, err := g.config(); err != nil {
				return err
			}
			if g.configPath == "" {
				return errors.New("no configuration file: set --config or OPB_CONFIG")
			}
			if err := client.SetCurrentContext(g.configPath, args[0]); err != nil {
				return err
			}
			fmt.Printf("current context set to %q in %s\n", args[0], g.configPath)
			if override := cmp.Or(g.context, g.getenv("OPB_CONTEXT")); override != "" && override != args[0] {
				fmt.Fprintf(os.Stderr, "opb: note: --context or OPB_CONTEXT (%q) still takes precedence\n", override)
			}
			return nil
		},
	}
	cmd.AddCommand(list, show, use)
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "version",
		Short:             "Print the version",
		Args:              usageArgs(cobra.NoArgs),
		ValidArgsFunction: cobra.NoFileCompletions,
		Run: func(*cobra.Command, []string) {
			fmt.Printf("opb %s (commit %s, built %s)\n", version, commit, date)
		},
	}
}

// newGroupCmd returns a command that only holds subcommands. It is runnable
// so that a missing or unknown subcommand is an error, not a help screen
// with exit status 0.
func newGroupCmd(name, short string) *cobra.Command {
	return &cobra.Command{
		Use:   name + " <command>",
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &usageError{cmd, errors.New("missing command")}
			}
			return &usageError{cmd, fmt.Errorf("unknown command %q", args[0])}
		},
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

// usageError is a command line error: it is reported with a pointer to the
// command's help.
type usageError struct {
	cmd *cobra.Command
	err error
}

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usageArgs(validate cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := validate(cmd, args); err != nil {
			return &usageError{cmd, err}
		}
		return nil
	}
}

func fail(err error) int {
	if err == nil {
		return exitOK
	}
	fmt.Fprintln(os.Stderr, "opb:", err)
	if ue, ok := errors.AsType[*usageError](err); ok {
		fmt.Fprintf(os.Stderr, "Run '%s --help' for usage.\n", ue.cmd.CommandPath())
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
