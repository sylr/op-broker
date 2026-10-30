package client

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestWriteFileAtomicNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	if err := WriteFileAtomic(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, path); m != 0o600 {
		t.Fatalf("mode = %v", m)
	}
	if b, _ := os.ReadFile(path); string(b) != "secret" {
		t.Fatalf("content = %q", b)
	}
}

func TestWriteFileAtomicReplacesPermissiveFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, path); m != 0o600 {
		t.Fatalf("mode = %v, want 0600", m)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("content = %q", b)
	}
}

func TestWriteFileAtomicRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(link, []byte("secret")); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "untouched" {
		t.Fatalf("symlink target modified: %q", b)
	}
}

func TestWriteFileAtomicRefusesDirectory(t *testing.T) {
	if err := WriteFileAtomic(t.TempDir(), []byte("x")); err == nil {
		t.Fatal("wrote over a directory")
	}
}

func TestWriteFileAtomicNoTempLeftOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	var tmpName string
	rename = func(oldpath, newpath string) error {
		tmpName = oldpath
		if b, err := os.ReadFile(oldpath); err != nil || string(b) != "secret" {
			t.Errorf("temporary file does not hold the data before rename: %q, %v", b, err)
		}
		return errors.New("injected rename failure")
	}
	t.Cleanup(func() { rename = os.Rename })

	if err := WriteFileAtomic(path, []byte("secret")); err == nil {
		t.Fatal("expected error")
	}
	if tmpName == "" {
		t.Fatal("rename was never reached")
	}
	if _, err := os.Lstat(tmpName); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temporary file holding secrets left behind: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "previous" {
		t.Fatalf("destination modified: %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}
