//go:build !freebsd

package native

import (
	"Heimdall/internal/identity"
	"context"
	"os"
	"strconv"
	"strings"
)

const sudoDirectory = "/etc/sudoers.d"
const sudoMainFile = "/etc/sudoers"
const visudoBinary = "/usr/sbin/visudo"

func nativeShell(shell string) string { return shell }
func readPasswordState(byName map[string]localAccount) error {
	shadow, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(shadow), "\n") {
		p := strings.Split(line, ":")
		if len(p) == 9 {
			if a, ok := byName[p[0]]; ok {
				a.PasswordHash = p[1]
				a.Expire = p[7]
				byName[p[0]] = a
			}
		}
	}
	return nil
}
func groupAdd(ctx context.Context, name string, gid int) error {
	return command(ctx, "", "/usr/sbin/groupadd", "--gid", strconv.Itoa(gid), name)
}
func createUser(ctx context.Context, u identity.User) error {
	return command(ctx, "", "/usr/sbin/useradd", "--uid", strconv.Itoa(u.UID), "--gid", strconv.Itoa(u.GID), "--create-home", "--home-dir", u.Home, "--shell", "/usr/sbin/nologin", "--expiredate", "1970-01-02", u.Login)
}
func quarantineUser(ctx context.Context, login string) error {
	return command(ctx, "", "/usr/sbin/usermod", "--expiredate", "1970-01-02", login)
}
func setPassword(ctx context.Context, login, hash string) error {
	if hash == "*" {
		return command(ctx, "", "/usr/sbin/usermod", "--password", "*", login)
	}
	return command(ctx, login+":"+hash+"\n", "/usr/sbin/chpasswd", "--encrypted")
}
func activateUser(ctx context.Context, login, shell, gecos string, enabled bool) error {
	expire := "1970-01-02"
	if enabled {
		expire = ""
	}
	return command(ctx, "", "/usr/sbin/usermod", "--shell", shell, "--comment", gecos, "--expiredate", expire, login)
}
func migrateUser(ctx context.Context, old identity.User, u identity.User) error {
	args := []string{"--uid", strconv.Itoa(u.UID), "--gid", strconv.Itoa(u.GID), "--login", u.Login}
	if old.Home != u.Home {
		args = append(args, "--home", u.Home, "--move-home")
	}
	args = append(args, old.Login)
	return command(ctx, "", "/usr/sbin/usermod", args...)
}
func interruptedHomeMove(previous identity.User, u identity.User) bool { return false }

func disableForMigration(ctx context.Context, login string) error {
	return command(ctx, "", "/usr/sbin/usermod", "--expiredate", "1970-01-02", "--shell", "/usr/sbin/nologin", "--password", "*", login)
}

func setGroups(ctx context.Context, login string, names []string) error {
	return command(ctx, "", "/usr/sbin/usermod", "--groups", strings.Join(names, ","), login)
}
