package agent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeLaunchctl models one launchd job. After a bootout, print keeps
// reporting it loaded for lingering more calls, like a job still exiting.
type fakeLaunchctl struct {
	calls     [][]string
	loaded    bool
	lingering int
	fail      map[string]error
}

func (f *fakeLaunchctl) run(args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if err := f.fail[args[0]]; err != nil {
		return []byte("launchctl said no"), err
	}
	switch args[0] {
	case "print":
		if f.lingering > 0 {
			f.lingering--
			return nil, nil
		}
		if !f.loaded {
			return []byte("Could not find service"), errors.New("exit status 113")
		}
	case "bootout":
		f.loaded = false
	case "bootstrap":
		f.loaded = true
	}
	return nil, nil
}

func init() { unloadPoll = time.Millisecond }

func spec(home string) Spec {
	return Spec{
		Opbd:   "/opt/homebrew/bin/opbd",
		Config: filepath.Join(home, "Library/Application Support/op-broker/config.yaml"),
		Stderr: filepath.Join(home, "Library/Logs/op-broker.stderr.log"),
	}
}

func TestInstall(t *testing.T) {
	home := t.TempDir()
	lc := &fakeLaunchctl{}

	path, err := Install(home, 501, spec(home), lc.run)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, "Library/LaunchAgents/com.sylr.op-broker.plist"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	want := [][]string{
		{"print", "gui/501/com.sylr.op-broker"},
		{"bootstrap", "gui/501", path},
	}
	if !reflect.DeepEqual(lc.calls, want) {
		t.Errorf("launchctl calls = %q, want %q", lc.calls, want)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"<string>/opt/homebrew/bin/opbd</string>",
		"<string>" + home + "/Library/Application Support/op-broker/config.yaml</string>",
		"<string>" + home + "/Library/Logs/op-broker.stderr.log</string>",
	} {
		if !strings.Contains(string(b), s) {
			t.Errorf("plist lacks %s:\n%s", s, b)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("plist mode = %v, want 0644", fi.Mode().Perm())
	}
}

func TestInstallBootstrapError(t *testing.T) {
	home := t.TempDir()
	lc := &fakeLaunchctl{fail: map[string]error{"bootstrap": errors.New("exit status 5")}}
	_, err := Install(home, 501, spec(home), lc.run)
	if err == nil || !strings.Contains(err.Error(), "launchctl said no") {
		t.Fatalf("err = %v, want the launchctl output", err)
	}
}

func TestInstallRelativePath(t *testing.T) {
	home := t.TempDir()
	s := spec(home)
	s.Opbd = "opbd"
	lc := &fakeLaunchctl{}
	if _, err := Install(home, 501, s, lc.run); err == nil {
		t.Fatal("relative opbd path accepted")
	}
	if len(lc.calls) != 0 {
		t.Errorf("launchctl called: %q", lc.calls)
	}
}

func TestReinstallWaitsForUnload(t *testing.T) {
	home := t.TempDir()
	path := Path(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// An older plist that launchd would reject: group-writable.
	if err := os.WriteFile(path, []byte("old"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	lc := &fakeLaunchctl{loaded: true}
	lc.fail = nil
	// The old job is still exiting for two polls after bootout.
	wrapped := func(args ...string) ([]byte, error) {
		if args[0] == "bootout" {
			lc.lingering = 2
		}
		return lc.run(args...)
	}
	if _, err := Install(home, 501, spec(home), wrapped); err != nil {
		t.Fatal(err)
	}
	target := "gui/501/com.sylr.op-broker"
	want := [][]string{
		{"print", target},
		{"bootout", target},
		{"print", target},
		{"print", target},
		{"print", target},
		{"bootstrap", "gui/501", path},
	}
	if !reflect.DeepEqual(lc.calls, want) {
		t.Errorf("launchctl calls = %q, want %q", lc.calls, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("plist mode = %v, want 0644", fi.Mode().Perm())
	}
}

func TestInstallBootoutError(t *testing.T) {
	home := t.TempDir()
	lc := &fakeLaunchctl{loaded: true, fail: map[string]error{"bootout": errors.New("exit status 5")}}
	if _, err := Install(home, 501, spec(home), lc.run); err == nil || !strings.Contains(err.Error(), "bootout") {
		t.Fatalf("err = %v, want the bootout failure", err)
	}
	for _, c := range lc.calls {
		if c[0] == "bootstrap" {
			t.Errorf("bootstrap after a failed bootout: %q", lc.calls)
		}
	}
}

func TestUnloadTimeout(t *testing.T) {
	defer func(d time.Duration) { unloadTimeout = d }(unloadTimeout)
	unloadTimeout = 5 * time.Millisecond
	// bootout "succeeds" but the job never goes away.
	stuck := func(args ...string) ([]byte, error) { return nil, nil }
	if _, err := Install(t.TempDir(), 501, spec("/h"), stuck); err == nil || !strings.Contains(err.Error(), "still loaded") {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

func TestUninstall(t *testing.T) {
	home := t.TempDir()
	lc := &fakeLaunchctl{}
	path, err := Install(home, 501, spec(home), lc.run)
	if err != nil {
		t.Fatal(err)
	}

	lc.calls = nil
	if _, err := Uninstall(home, 501, lc.run); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("plist still present: %v", err)
	}
	target := "gui/501/com.sylr.op-broker"
	if want := [][]string{{"print", target}, {"bootout", target}, {"print", target}}; !reflect.DeepEqual(lc.calls, want) {
		t.Errorf("launchctl calls = %q, want %q", lc.calls, want)
	}

	// Already absent and not loaded.
	if _, err := Uninstall(home, 501, lc.run); err != nil {
		t.Errorf("second uninstall: %v", err)
	}
}

func TestUninstallBootoutError(t *testing.T) {
	home := t.TempDir()
	lc := &fakeLaunchctl{}
	path, err := Install(home, 501, spec(home), lc.run)
	if err != nil {
		t.Fatal(err)
	}
	lc.fail = map[string]error{"bootout": errors.New("exit status 1")}
	if _, err := Uninstall(home, 501, lc.run); err == nil {
		t.Fatal("uninstall succeeded although bootout failed")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("plist removed although the agent still runs: %v", err)
	}
}

func TestRenderEscapes(t *testing.T) {
	s := Spec{Opbd: "/a&b/opbd", Config: "/c<d>/config.yaml", Stderr: "/e/f.log"}
	b, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<string>/a&amp;b/opbd</string>", "<string>/c&lt;d&gt;/config.yaml</string>"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("plist lacks %s:\n%s", want, b)
		}
	}
}

// The plist must be one launchd accepts; plutil only exists on macOS.
func TestRenderLint(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("plutil is macOS only")
	}
	plutil, err := exec.LookPath("plutil")
	if err != nil {
		t.Skip("plutil not found")
	}
	b, err := Render(spec("/Users/someone"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent.plist")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(plutil, "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint: %v: %s", err, out)
	}
}
