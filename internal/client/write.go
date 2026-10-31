package client

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// rename is replaced in tests to exercise failures after secrets have been
// written to the temporary file.
var rename = os.Rename

// WriteFileAtomic writes data to path with mode 0600, replacing any existing
// file atomically. It refuses to write through a symlink or over anything
// that is not a regular file. Existing permissions are not preserved: the
// result is always 0600.
func WriteFileAtomic(path string, data []byte) error {
	return writeFileAtomic(path, data, 0o600)
}

// writeFileAtomic is WriteFileAtomic with the given permissions.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s is a symlink; refusing to write secrets through it", path)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", path)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".opb-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return rename(tmp.Name(), path)
}
