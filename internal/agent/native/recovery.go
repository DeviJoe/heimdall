package native

import (
	"Heimdall/internal/synchronization"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

type journal struct {
	State  synchronization.Snapshot `json:"state"`
	Digest string                   `json:"digest"`
}

func (e *Executor) readJournal(name string) (journal, error) {
	var j journal
	path := filepath.Join(e.StateDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return j, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return j, errors.New("unsafe root journal")
	}
	file, err := os.Open(path)
	if err != nil {
		return j, err
	}
	defer file.Close()
	err = json.NewDecoder(io.LimitReader(file, 32<<20)).Decode(&j)
	return j, err
}

// Recovery uses only a root-owned journal created after the helper verified a control-plane signature.
func (e *Executor) Recover(ctx context.Context) error {
	j, err := e.readJournal("pending.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// A matching checkpoint is not proof that local files still match. A drift
	// repair can fail while replaying the same revision; replay the journal too.
	result, err := e.Apply(ctx, j.State, j.Digest)
	if err != nil {
		return err
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}
func (e *Executor) cache(s synchronization.Snapshot, digest string) error {
	var previous synchronization.Snapshot
	if !s.Full {
		old, err := e.readJournal("desired.json")
		if err != nil {
			return err
		}
		previous = old.State
	}
	s, err := materializeDesired(previous, s)
	if err != nil {
		return err
	}
	data, err := json.Marshal(journal{s, digest})
	if err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(e.StateDir, "desired.json"), data, 0600)
}

// A delta contains only the group definitions needed by its changed accounts.
// The durable full manifest must retain definitions used by unchanged accounts,
// so offline reconciliation can replay the same native memberships.
func materializeDesired(previous, s synchronization.Snapshot) (synchronization.Snapshot, error) {
	desired := map[string]synchronization.Account{}
	groups := map[string]synchronization.UnixGroup{}
	if !s.Full {
		if previous.NodeID != s.NodeID || previous.Epoch != s.Epoch {
			return s, errors.New("delta cache identity mismatch")
		}
		for _, a := range previous.Accounts {
			desired[a.User.ID] = a
		}
		for _, g := range previous.Groups {
			groups[g.Name] = g
		}
	}
	for _, a := range s.Accounts {
		desired[a.User.ID] = a
	}
	for _, g := range s.Groups {
		if old, exists := groups[g.Name]; exists && old != g {
			return s, errors.New("delta changes managed UNIX group identity")
		}
		groups[g.Name] = g
	}
	s.Full = true
	s.BaseRevision = 0
	s.Accounts = nil
	for _, a := range desired {
		s.Accounts = append(s.Accounts, a)
	}
	sort.Slice(s.Accounts, func(i, j int) bool { return s.Accounts[i].User.Login < s.Accounts[j].User.Login })
	s.Groups = nil
	for _, g := range groups {
		s.Groups = append(s.Groups, g)
	}
	sort.Slice(s.Groups, func(i, j int) bool { return s.Groups[i].Name < s.Groups[j].Name })
	return s, Validate(s)
}
func (e *Executor) Reconcile(ctx context.Context) error {
	if _, err := os.Lstat(filepath.Join(e.StateDir, "pending.json")); err == nil {
		return e.Recover(ctx)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	j, err := e.readJournal("desired.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	r, err := e.Apply(ctx, j.State, j.Digest)
	if err != nil {
		return err
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	return nil
}
func matches(a synchronization.Account, actual localAccount) bool {
	hash := "*"
	expire := "1"
	shell := "/usr/sbin/nologin"
	keys := ""
	sudo := "# Managed by Heimdall\n"
	if a.Enabled {
		expire = ""
		shell = nativeShell(a.User.Shell)
		keys = KeyFile(a)
		if a.PasswordHash != "" {
			hash = a.PasswordHash
		}
		if len(a.Sudo) > 0 || len(a.Sudoers) > 0 {
			sudo += SudoFile(a)
		}
	}
	if actual.Shell != shell || actual.GECOS != a.User.GECOS || actual.PasswordHash != hash || actual.Expire != expire {
		return false
	}
	for path, want := range map[string]string{filepath.Join(managedDirectory, "authorized_keys", a.User.Login): keys, filepath.Join(sudoDirectory, sudoPrefix()+a.User.Login): sudo} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		content, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(content, []byte(want)) {
			return false
		}
	}
	return true
}
