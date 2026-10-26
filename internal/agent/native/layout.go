package native

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

var managedDirectory = chooseManagedDirectory()

func chooseManagedDirectory() string {
	if info, err := os.Lstat("/etc/linpam/users"); err == nil && info.IsDir() {
		return "/etc/linpam"
	}
	return "/etc/heimdall"
}
func ManagedDirectory() string { return managedDirectory }
func sudoPrefix() string {
	if managedDirectory == "/etc/linpam" {
		return "linpam_"
	}
	return "heimdall_"
}

// A FreeBSD /home -> /usr/home alias is an OS convention. Only that exact,
// root-owned alias is accepted; arbitrary links remain forbidden.
func validateHomeBase(home string) error {
	base := filepath.Dir(home)
	info, err := os.Lstat(base)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(base, 0755); err != nil {
			return err
		}
		info, err = os.Lstat(base)
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("home base must be root-owned and non-writable")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(base)
		if runtime.GOOS != "freebsd" || err != nil || base != "/home" || target != "/usr/home" {
			return errors.New("unsafe home base symlink")
		}
		info, err = os.Stat(target)
		if err != nil {
			return err
		}
		stat, ok = info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe FreeBSD home base")
		}
	}
	if info.Mode().Perm()&0022 != 0 {
		return errors.New("home base must be non-writable")
	}
	if !info.IsDir() {
		return errors.New("invalid home base")
	}
	return nil
}
