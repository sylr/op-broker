//go:build unix

package client

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLoadConfigFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opb.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadConfig(path, true); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadConfig blocked on a FIFO")
	}
}

func TestLoadConfigWritableDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opb.yaml")
	if err := os.WriteFile(path, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path, true); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("config in a world-writable directory: %v", err)
	}
}

func TestLoadConfigSymlinkChain(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	shared := filepath.Join(base, "shared")
	for _, d := range []string{home, shared} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// home/opb.yaml -> shared/active.yaml -> shared/real.yaml
	if err := os.WriteFile(filepath.Join(shared, "real.yaml"), []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.yaml", filepath.Join(shared, "active.yaml")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "opb.yaml")
	if err := os.Symlink(filepath.Join(shared, "active.yaml"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path, true); err != nil {
		t.Fatalf("private symlink chain: %v", err)
	}

	// Another user could repoint the intermediate link.
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path, true); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("symlink through a writable directory: %v", err)
	}
	// Sticky directories (/tmp, /nix/store) only let owners replace entries.
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path, true); err != nil {
		t.Fatalf("symlink through a sticky directory: %v", err)
	}
}
