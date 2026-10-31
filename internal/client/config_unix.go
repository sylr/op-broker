//go:build unix

package client

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// maxSymlinks bounds the symlink chain followed to the configuration.
const maxSymlinks = 40

// checkOwner requires fi to belong to the current user or to root (e.g. a
// file in the Nix store).
func checkOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	if uid := int(st.Uid); uid != os.Getuid() && uid != 0 {
		return fmt.Errorf("%s is not owned by the current user or root", path)
	}
	return nil
}

// checkConfigFile requires the open configuration file to belong to the
// current user or root and not to be writable by group or others.
func checkConfigFile(path string, fi os.FileInfo) error {
	if err := checkOwner(path, fi); err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others (mode %v); chmod go-w it", path, fi.Mode().Perm())
	}
	return nil
}

// checkConfigPath requires every directory that could redirect path to
// another file to be owned by the current user or root and not writable by
// group or others, unless sticky (as /tmp and /nix/store are). It checks the
// ancestors of path and of every symlink target on the way to the file,
// both as written and with symlinks resolved, like ssh's StrictModes but
// along the whole chain.
func checkConfigPath(path string) error {
	p, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for range maxSymlinks {
		dir := filepath.Dir(p)
		if err := checkAncestors(dir); err != nil {
			return err
		}
		real, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return err
		}
		if real != dir {
			if err := checkAncestors(real); err != nil {
				return err
			}
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			return nil
		}
		target, err := os.Readlink(p)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		p = target
	}
	return fmt.Errorf("%s: too many levels of symbolic links", path)
}

func checkAncestors(dir string) error {
	for {
		fi, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return &fs.PathError{Op: "stat", Path: dir, Err: errors.New("not a directory")}
		}
		if err := checkOwner(dir, fi); err != nil {
			return err
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSticky == 0 {
			return fmt.Errorf("%s is writable by group or others (mode %v), so the configuration could be replaced; chmod go-w it", dir, fi.Mode().Perm())
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}
