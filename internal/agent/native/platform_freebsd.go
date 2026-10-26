package native

import (
	"Heimdall/internal/identity"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const sudoDirectory = "/usr/local/etc/sudoers.d"
const sudoMainFile = "/usr/local/etc/sudoers"
const visudoBinary = "/usr/local/sbin/visudo"

func nativeShell(shell string) string {
	if shell == "/bin/bash" {
		return "/usr/local/bin/bash"
	}
	return shell
}
func readPasswordState(byName map[string]localAccount) error {
	data, err := os.ReadFile("/etc/master.passwd")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.Split(line, ":")
		if len(p) != 10 {
			continue
		}
		if a, ok := byName[p[0]]; ok {
			a.PasswordHash = p[1]
			a.Expire = p[6]
			if a.Expire == "0" {
				a.Expire = ""
			} else if a.Expire == "86400" {
				a.Expire = "1"
			}
			byName[p[0]] = a
		}
	}
	return nil
}
func groupAdd(ctx context.Context, name string, gid int) error {
	return command(ctx, "", "/usr/sbin/pw", "groupadd", "-n", name, "-g", strconv.Itoa(gid))
}
func createUser(ctx context.Context, u identity.User) error {
	return command(ctx, "", "/usr/sbin/pw", "useradd", "-n", u.Login, "-u", strconv.Itoa(u.UID), "-g", strconv.Itoa(u.GID), "-m", "-d", u.Home, "-s", "/usr/sbin/nologin", "-e", "86400", "-h", "-")
}
func quarantineUser(ctx context.Context, login string) error {
	return command(ctx, "", "/usr/sbin/pw", "usermod", "-n", login, "-e", "86400")
}
func setPassword(ctx context.Context, login, hash string) error {
	if hash == "*" {
		return command(ctx, "", "/usr/sbin/pw", "usermod", "-n", login, "-h", "-")
	}
	return command(ctx, hash+"\n", "/usr/sbin/pw", "usermod", "-n", login, "-H", "0")
}
func activateUser(ctx context.Context, login, shell, gecos string, enabled bool) error {
	expire := "86400"
	if enabled {
		expire = "0"
	}
	return command(ctx, "", "/usr/sbin/pw", "usermod", "-n", login, "-s", nativeShell(shell), "-c", gecos, "-e", expire)
}
func disableForMigration(ctx context.Context, login string) error {
	if err := quarantineUser(ctx, login); err != nil {
		return err
	}
	if err := setPassword(ctx, login, "*"); err != nil {
		return err
	}
	return activateUser(ctx, login, "/usr/sbin/nologin", "", false)
}
func interruptedHomeMove(previous identity.User, u identity.User) bool {
	if _, err := os.Lstat(previous.Home); !os.IsNotExist(err) {
		return false
	}
	info, err := os.Lstat(u.Home)
	if err != nil || !info.IsDir() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (int(stat.Uid) == previous.UID || int(stat.Uid) == u.UID)
}
func migrateUser(ctx context.Context, previous identity.User, u identity.User) error {
	if err := validateHomeBase(u.Home); err != nil {
		return err
	}
	if previous.Home != u.Home {
		if _, err := os.Lstat(previous.Home); err == nil {
			if err = os.Rename(previous.Home, u.Home); err != nil {
				return err
			}
		} else if !interruptedHomeMove(previous, u) {
			return errors.New("managed home migration cannot be recovered")
		}
	}
	return command(ctx, "", "/usr/sbin/pw", "usermod", "-n", previous.Login, "-u", strconv.Itoa(u.UID), "-g", strconv.Itoa(u.GID), "-l", u.Login, "-d", u.Home)
}

func setGroups(ctx context.Context, login string, names []string) error {
	return command(ctx, "", "/usr/sbin/pw", "usermod", "-n", login, "-G", strings.Join(names, ","))
}
