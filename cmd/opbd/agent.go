package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sylr/op-broker/internal/agent"
	"github.com/sylr/op-broker/internal/config"
)

const agentUsage = `Usage:
  opbd agent install [-config path] [-opbd path]
  opbd agent uninstall

install writes ~/Library/LaunchAgents/` + agent.Label + `.plist and loads
it, so launchd runs opbd in your GUI session at login and restarts it if it
exits. It checks the configuration first. Run it again after moving opbd or
the configuration. uninstall stops the agent and removes the plist.
`

// agentMain runs "opbd agent <args>".
func agentMain(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("missing subcommand\n\n" + agentUsage)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("opbd agent "+args[0], flag.ContinueOnError)
	fs.SetOutput(stdout)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), agentUsage)
		if args[0] == "install" {
			fmt.Fprint(fs.Output(), "\nFlags of install:\n")
			fs.PrintDefaults()
		}
	}

	// A LaunchAgent belongs to the user's GUI session. Under sudo, uid 0 has
	// no such session and the plist would end up owned by root.
	if os.Geteuid() == 0 && args[0] != "-h" && args[0] != "-help" && args[0] != "--help" && args[0] != "help" {
		return errors.New("run as your own user, not root")
	}

	switch args[0] {
	case "install":
		configPath := fs.String("config", config.DefaultPath(), "configuration file the agent runs with")
		opbdPath := fs.String("opbd", "", "opbd binary the agent runs (default: this binary)")
		if err := fs.Parse(args[1:]); err != nil {
			return ignoreHelp(err)
		}
		if fs.NArg() > 0 {
			return fmt.Errorf("unexpected arguments: %q", fs.Args())
		}
		if runtime.GOOS != "darwin" {
			return errors.New("LaunchAgents only exist on macOS")
		}
		spec, warning, err := agentSpec(home, *configPath, *opbdPath)
		if err != nil {
			return err
		}
		if err := checkExecutable(spec.Opbd); err != nil {
			return err
		}
		// A broken configuration would make launchd restart opbd forever.
		if _, _, err := config.Load(spec.Config); err != nil {
			return fmt.Errorf("checking %s: %w", spec.Config, err)
		}
		if warning != "" {
			fmt.Fprintln(stdout, "warning:", warning)
		}
		path, err := agent.Install(home, os.Getuid(), spec, agent.ExecLaunchctl)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "installed %s\nlaunchd now runs %s -config %q\nstartup errors and tailnet login messages: %s\n",
			path, spec.Opbd, spec.Config, spec.Stderr)
		return nil

	case "uninstall":
		if err := fs.Parse(args[1:]); err != nil {
			return ignoreHelp(err)
		}
		if fs.NArg() > 0 {
			return fmt.Errorf("unexpected arguments: %q", fs.Args())
		}
		if runtime.GOOS != "darwin" {
			return errors.New("LaunchAgents only exist on macOS")
		}
		path, err := agent.Uninstall(home, os.Getuid(), agent.ExecLaunchctl)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "removed %s\n", path)
		return nil

	case "-h", "-help", "--help", "help":
		fs.Usage()
		return nil

	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], agentUsage)
	}
}

// agentSpec resolves the paths the LaunchAgent runs with. opbdPath defaults
// to the running binary. The returned warning is set when that path is
// inside a package store whose paths change on upgrade.
func agentSpec(home, configPath, opbdPath string) (agent.Spec, string, error) {
	configPath, err := config.ExpandHome(configPath)
	if err != nil {
		return agent.Spec{}, "", err
	}
	if configPath, err = filepath.Abs(configPath); err != nil {
		return agent.Spec{}, "", err
	}

	if opbdPath == "" {
		// The path opbd was started with, not its symlink target: the
		// target of /opt/homebrew/bin/opbd or ~/.nix-profile/bin/opbd
		// changes on every upgrade.
		if opbdPath, err = os.Executable(); err != nil {
			return agent.Spec{}, "", err
		}
	}
	if opbdPath, err = config.ExpandHome(opbdPath); err != nil {
		return agent.Spec{}, "", err
	}
	if opbdPath, err = filepath.Abs(opbdPath); err != nil {
		return agent.Spec{}, "", err
	}

	var warning string
	for _, dir := range []string{"/Caskroom/", "/Cellar/", "/nix/store/"} {
		if strings.Contains(opbdPath, dir) {
			warning = fmt.Sprintf("%s is inside a package store and changes on upgrade; "+
				"run opbd through its symlink (e.g. /opt/homebrew/bin/opbd) or pass -opbd", opbdPath)
			break
		}
	}

	return agent.Spec{
		Opbd:   opbdPath,
		Config: configPath,
		Stderr: filepath.Join(home, "Library", "Logs", "op-broker.stderr.log"),
	}, warning, nil
}

// checkExecutable fails unless path is an executable regular file, so a
// typo does not leave launchd restarting a missing binary forever.
func checkExecutable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not an executable file", path)
	}
	return nil
}

// ignoreHelp turns the -h error of flag.FlagSet.Parse, which has already
// printed the usage, into success.
func ignoreHelp(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}
