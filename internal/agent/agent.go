// Package agent installs and removes the opbd LaunchAgent.
//
// opbd must run as a LaunchAgent in the user's GUI session, not as a
// LaunchDaemon: 1Password desktop-app integration needs the user session.
package agent

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"text/template"
	"time"
)

// Label is the launchd label of the opbd LaunchAgent.
const Label = "com.sylr.op-broker"

// Spec describes the LaunchAgent to install.
type Spec struct {
	// Opbd is the absolute path of the opbd binary launchd runs. Keep the
	// path of a stable symlink (e.g. /opt/homebrew/bin/opbd), not its
	// target: package upgrades replace the target.
	Opbd string
	// Config is the absolute path of the configuration file.
	Config string
	// Stderr is the absolute path that receives opbd's standard error.
	Stderr string
}

// Launchctl runs launchctl with args and returns its combined output.
type Launchctl func(args ...string) ([]byte, error)

// ExecLaunchctl runs /bin/launchctl.
func ExecLaunchctl(args ...string) ([]byte, error) {
	return exec.Command("/bin/launchctl", args...).CombinedOutput()
}

// Path is the plist path of the LaunchAgent in home.
func Path(home string) string {
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist")
}

// Domain is the launchd GUI domain of the user uid.
func Domain(uid int) string {
	return "gui/" + strconv.Itoa(uid)
}

// Install writes the LaunchAgent plist for spec in home and (re)loads it in
// the GUI domain of uid, replacing any agent already loaded under Label.
func Install(home string, uid int, spec Spec, launchctl Launchctl) (string, error) {
	for name, p := range map[string]string{"opbd": spec.Opbd, "config": spec.Config, "stderr": spec.Stderr} {
		if !filepath.IsAbs(p) {
			return "", fmt.Errorf("%s path must be absolute: %q", name, p)
		}
	}
	plist, err := Render(spec)
	if err != nil {
		return "", err
	}
	path := Path(home)
	if err := writeFileAtomic(path, plist, 0o644); err != nil {
		return "", err
	}
	if err := unload(uid, launchctl); err != nil {
		return "", err
	}
	if out, err := launchctl("bootstrap", Domain(uid), path); err != nil {
		return "", fmt.Errorf("launchctl bootstrap %s %s: %w: %s", Domain(uid), path, err, bytes.TrimSpace(out))
	}
	return path, nil
}

// Uninstall unloads the LaunchAgent from the GUI domain of uid and removes
// its plist from home. It succeeds when the agent is already absent.
func Uninstall(home string, uid int, launchctl Launchctl) (string, error) {
	if err := unload(uid, launchctl); err != nil {
		return "", err
	}
	path := Path(home)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return path, nil
}

// Polling of launchctl while an unloaded job exits. opbd shuts tsnet down
// on SIGTERM, which takes a moment.
var (
	unloadPoll    = 200 * time.Millisecond
	unloadTimeout = 15 * time.Second
)

// unload boots the agent out of the GUI domain of uid if it is loaded, and
// waits until launchd has removed the job: bootstrapping the same label
// before that fails.
func unload(uid int, launchctl Launchctl) error {
	target := Domain(uid) + "/" + Label
	if _, err := launchctl("print", target); err != nil {
		return nil // not loaded
	}
	if out, err := launchctl("bootout", target); err != nil {
		return fmt.Errorf("launchctl bootout %s: %w: %s", target, err, bytes.TrimSpace(out))
	}
	for deadline := time.Now().Add(unloadTimeout); time.Now().Before(deadline); time.Sleep(unloadPoll) {
		if _, err := launchctl("print", target); err != nil {
			return nil
		}
	}
	return fmt.Errorf("%s still loaded %s after bootout", target, unloadTimeout)
}

// writeFileAtomic replaces path with data and mode, so launchd never reads a
// partial plist and an older file's permissions do not survive.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after the rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Render returns the LaunchAgent plist for spec.
func Render(spec Spec) ([]byte, error) {
	var buf bytes.Buffer
	if err := plistTemplate.Execute(&buf, spec); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var plistTemplate = template.Must(template.New("plist").Funcs(template.FuncMap{
	"x":     xmlEscape,
	"label": func() string { return Label },
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!-- Written by "opbd agent install". Remove with "opbd agent uninstall". -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{{ label }}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{{ x .Opbd }}</string>
    <string>-config</string>
    <string>{{ x .Config }}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>30</integer>
  <key>ProcessType</key>
  <string>Interactive</string>
  <!-- 077: files created by opbd are private to the user. -->
  <key>Umask</key>
  <integer>63</integer>
  <!-- Startup errors and tsnet login messages; the audit log goes to log_file. -->
  <key>StandardErrorPath</key>
  <string>{{ x .Stderr }}</string>
</dict>
</plist>
`))

func xmlEscape(s string) (string, error) {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return "", err
	}
	return buf.String(), nil
}
