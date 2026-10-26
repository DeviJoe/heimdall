package native

import (
	"errors"
	"os"
	"path/filepath"
)

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe parent directory")
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to replace symlink")
	}
	f, err := os.CreateTemp(parent, ".linpam-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	d, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
