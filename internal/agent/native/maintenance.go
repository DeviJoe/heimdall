package native

import (
	"Heimdall/internal/identity"
	"Heimdall/internal/synchronization"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func (e *Executor) managedGroup(ctx context.Context, u identity.User, names map[int]string) error {
	path := filepath.Join(managedDirectory, "groups", strconv.Itoa(u.GID)+".json")
	if group := names[u.GID]; group != "" {
		data, err := os.ReadFile(path)
		var owner struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			GID  int    `json:"gid"`
		}
		if err != nil || json.Unmarshal(data, &owner) != nil || owner.Name != group || owner.GID != u.GID {
			// Adopt only a group already created by a previous version for this managed account.
			data, err = os.ReadFile(filepath.Join(managedDirectory, "users", group+".json"))
			var previous identity.User
			if err != nil || json.Unmarshal(data, &previous) != nil || previous.Login != group || previous.GID != u.GID {
				return errors.New("GID belongs to an unmanaged group")
			}
			encoded, _ := json.Marshal(map[string]any{"name": group, "gid": u.GID})
			return AtomicWrite(path, encoded, 0600)
		}
		return nil
	}
	name := sudoPrefix() + "gid_" + strconv.Itoa(u.GID)
	if err := groupAdd(ctx, name, u.GID); err != nil {
		return err
	}
	names[u.GID] = name
	encoded, _ := json.Marshal(map[string]any{"name": name, "gid": u.GID})
	return AtomicWrite(path, encoded, 0600)
}
func (e *Executor) migrate(ctx context.Context, a synchronization.Account, previous identity.User, local map[string]localAccount, uidNames map[int]string, groupNames map[int]string) error {
	u := a.User
	if a.Enabled {
		return errors.New("POSIX migration requires confirmed account disablement")
	}
	actualLogin := previous.Login
	old, exists := local[previous.Login]
	if !exists {
		old, exists = local[u.Login]
		actualLogin = u.Login
	}
	if !exists {
		return errors.New("previous managed account missing")
	}
	already := actualLogin == u.Login && old.UID == u.UID && old.GID == u.GID && old.Home == u.Home && old.Shell == "/usr/sbin/nologin" && old.Expire == "1" && old.PasswordHash == "*"

	data, err := os.ReadFile(filepath.Join(managedDirectory, "users", previous.Login+".json"))
	var owner identity.User
	if err != nil || json.Unmarshal(data, &owner) != nil || owner.ID != u.ID {
		return errors.New("previous account ownership mismatch")
	}
	if !already && (owner.UID != old.UID || owner.GID != old.GID || owner.Home != old.Home) {
		return errors.New("local POSIX drift requires manual recovery")
	}
	if name := uidNames[u.UID]; name != "" && name != previous.Login && (!already || name != u.Login) {
		return errors.New("target UID already allocated")
	}
	if newAccount, exists := local[u.Login]; exists && u.Login != previous.Login && newAccount.UID != old.UID {
		return errors.New("target login already allocated")
	}
	if !already && old.Home != u.Home {
		if _, err = os.Lstat(u.Home); (err == nil || !errors.Is(err, os.ErrNotExist)) && !interruptedHomeMove(previous, u) {
			return errors.New("target home already exists or cannot be inspected")
		}
	}
	if err = e.managedGroup(ctx, u, groupNames); err != nil {
		return err
	}
	if !already {
		if e.revocations != nil {
			if err = e.revocations.add(ctx, previous); err != nil {
				return err
			}
			// usermod/pw cannot safely change an identity with live processes.
			if err = disableForMigration(ctx, previous.Login); err != nil {
				return err
			}
			if err = e.revocations.finish(ctx)[previous.ID]; err != nil {
				return err
			}
		}
		if err = disableForMigration(ctx, previous.Login); err != nil {
			return err
		}
		if err = AtomicWrite(filepath.Join(managedDirectory, "authorized_keys", previous.Login), nil, 0644); err != nil {
			return err
		}
		oldDisabled := synchronization.Account{User: previous}
		if err = e.sudo(ctx, oldDisabled); err != nil {
			return err
		}
		if err = migrateUser(ctx, previous, u); err != nil {
			return err
		}
	}

	root, err := os.OpenRoot(u.Home)
	if err != nil {
		return err
	}
	defer root.Close()
	err = filepath.WalkDir(u.Home, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(u.Home, path)
		if err != nil {
			return err
		}
		info, err := root.Lstat(relative)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot inspect ownership")
		}
		uid, gid := -1, -1
		if int(stat.Uid) == previous.UID {
			uid = u.UID
		}
		if int(stat.Gid) == previous.GID {
			gid = u.GID
		}
		if uid != -1 || gid != -1 {
			return root.Lchown(relative, uid, gid)
		}
		return nil
	})
	if err != nil {
		return err
	}
	metadata, _ := json.Marshal(u)
	if err = AtomicWrite(filepath.Join(managedDirectory, "users", u.Login+".json"), metadata, 0600); err != nil {
		return err
	}
	delete(local, previous.Login)
	delete(uidNames, old.UID)
	local[u.Login] = localAccount{UID: u.UID, GID: u.GID, Home: u.Home}
	uidNames[u.UID] = u.Login
	return nil
}

func (e *Executor) applyNamedGroup(ctx context.Context, g synchronization.UnixGroup, names map[int]string) error {
	path := filepath.Join(managedDirectory, "groups", strconv.Itoa(g.GID)+".json")
	if name := names[g.GID]; name != "" {
		var owner struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			GID  int    `json:"gid"`
		}
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &owner) != nil || owner.GID != g.GID || owner.Name != name || owner.ID != g.ID {
			return errors.New("UNIX GID belongs to an unmanaged group")
		}
		if name != g.Name {
			return errors.New("UNIX GID already has another managed name; migrate to a new group")
		}
		return nil
	}
	for _, name := range names {
		if name == g.Name {
			return errors.New("UNIX group name belongs to another GID")
		}
	}
	data, _ := json.Marshal(map[string]any{"id": g.ID, "name": g.Name, "gid": g.GID})
	if err := AtomicWrite(path, data, 0600); err != nil {
		return err
	}
	if err := groupAdd(ctx, g.Name, g.GID); err != nil {
		return err
	}
	names[g.GID] = g.Name
	return nil
}
func groupMemberships() (map[string][]string, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.Split(line, ":")
		if len(p) != 4 {
			continue
		}
		for _, login := range strings.Split(p[3], ",") {
			if login != "" {
				out[login] = append(out[login], p[0])
			}
		}
	}
	return out, nil
}
func sameGroups(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	members := map[string]bool{}
	for _, name := range a {
		members[name] = true
	}
	for _, name := range b {
		if !members[name] {
			return false
		}
	}
	return true
}
