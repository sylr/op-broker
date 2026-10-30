// Command opb is the 1password-broker client. It resolves 1Password secret
// references through an opbd server on the tailnet, with a subset of the op
// CLI interface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/sylr/1password-broker/internal/api"
	"github.com/sylr/1password-broker/internal/client"
)

const usage = `usage: opb [--server URL] <command> [flags]

Commands:
  read [-n] <op://vault/item/[section/]field>
  inject [-i template] [-o output]
  run [--env-file file]... -- <command> [args...]
  item get <item> --vault <vault> [--format json]
  version

The server defaults to $OPB_SERVER, then ` + client.DefaultServer + `.

Before sending anything, the client asks the local Tailscale daemon who owns
the server address and requires it to be --broker ($OPB_BROKER): user:<login>
(an untagged node of that user), tag:<name> or node:<stable-id>. By default the
server must be an untagged node owned by the same user as this machine; tagged
machines must set OPB_BROKER. --allow-non-tailnet (OPB_ALLOW_NON_TAILNET=1)
disables this check and the tailnet address restriction; use it only for
testing.

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

func run(args []string) int {
	global := flag.NewFlagSet("opb", flag.ContinueOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	server := global.String("server", "", "opbd server URL")
	broker := global.String("broker", os.Getenv("OPB_BROKER"), "expected tailnet identity of the server: user:<login>, tag:<name> or node:<stable-id> (default: untagged node of this machine's owner)")
	allowNonTailnet := global.Bool("allow-non-tailnet", os.Getenv("OPB_ALLOW_NON_TAILNET") == "1", "INSECURE, for testing: connect to any address and skip broker verification")
	if err := global.Parse(args); err != nil {
		return usageExit(err)
	}
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

	var err error
	addr := *server
	if addr == "" {
		addr = os.Getenv("OPB_SERVER")
	}
	if addr == "" {
		addr = client.DefaultServer
	}
	opts := client.Options{AllowNonTailnet: *allowNonTailnet}
	if !*allowNonTailnet {
		if opts.Verify, err = client.TailscaleVerifier(*broker); err != nil {
			return fail(err)
		}
	}
	c, err := client.New(addr, opts)
	if err != nil {
		return fail(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cmd, args := args[0], args[1:]
	switch cmd {
	case "read":
		err = cmdRead(ctx, c, args)
	case "inject":
		err = cmdInject(ctx, c, args)
	case "run":
		err = cmdRun(ctx, c, args)
	case "item":
		err = cmdItem(ctx, c, args)
	default:
		fmt.Fprintf(os.Stderr, "opb: unknown command %q\n\n%s", cmd, usage)
		return exitError
	}
	if err != nil {
		return fail(err)
	}
	return exitOK
}

func cmdRead(ctx context.Context, c *client.Client, args []string) error {
	fs := newFlagSet("read", "read [-n] <op://vault/item/[section/]field>")
	noNewline := fs.Bool("n", false, "do not print a trailing newline")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(fs)
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

func cmdInject(ctx context.Context, c *client.Client, args []string) error {
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

func cmdRun(ctx context.Context, c *client.Client, args []string) error {
	fs := newFlagSet("run", "run [--env-file file]... -- <command> [args...]\n\n"+
		"Environment variables whose whole value is an op:// reference are resolved\n"+
		"before <command> is executed. As with op run, env files override the process\n"+
		"environment, and later env files override earlier ones.\n\n"+
		"WARNING: unlike op run, the output of <command> is NOT masked: secrets it\n"+
		"prints will appear in clear.")
	var envFiles stringsFlag
	fs.Var(&envFiles, "env-file", "dotenv file to load (repeatable)")
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
	env := client.MergeEnv(os.Environ(), files...)
	values, err := resolveAll(ctx, c, client.EnvRefs(env))
	if err != nil {
		return err
	}
	if env, err = client.SubstituteEnv(env, values); err != nil {
		return err
	}
	return client.Exec(argv, env)
}

func cmdItem(ctx context.Context, c *client.Client, args []string) error {
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
