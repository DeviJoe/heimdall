package native

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/credentials"
	"Heimdall/internal/identity"
	"Heimdall/internal/synchronization"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Executor struct {
	StateDir    string
	sudoError   error
	memberships map[string][]string
	revocations *sessionRevocations
}
type localAccount struct {
	UID, GID                                 int
	Home, Shell, GECOS, PasswordHash, Expire string
}
type Checkpoint struct {
	NodeID   string                   `json:"node_id"`
	Epoch    string                   `json:"epoch"`
	Revision int64                    `json:"revision"`
	Digest   string                   `json:"digest"`
	Users    map[string]identity.User `json:"users"`
}

func New(stateDir string) (*Executor, error) {
	for _, path := range []string{stateDir, managedDirectory, managedDirectory + "/authorized_keys", managedDirectory + "/users", managedDirectory + "/groups", sudoDirectory} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("unsafe managed directory")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("managed directory must be root-owned and non-writable by other users")
		}
	}
	if err := os.Chmod(stateDir, 0700); err != nil {
		return nil, err
	}
	return &Executor{StateDir: stateDir}, nil
}
func (e *Executor) Checkpoint() (Checkpoint, error) {
	var c Checkpoint
	data, err := os.ReadFile(filepath.Join(e.StateDir, "checkpoint.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{Users: map[string]identity.User{}}, nil
	}
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(data, &c)
	return c, err
}
func accounts() (map[string]localAccount, map[int]string, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, nil, err
	}
	byName := map[string]localAccount{}
	byUID := map[int]string{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) != 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		byName[parts[0]] = localAccount{UID: uid, GID: gid, Home: parts[5], Shell: parts[6], GECOS: parts[4]}
		byUID[uid] = parts[0]
	}
	if err := readPasswordState(byName); err != nil {
		return nil, nil, err
	}
	return byName, byUID, nil
}
func groups() (map[int]string, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.Split(line, ":")
		if len(p) == 4 {
			gid, _ := strconv.Atoi(p[2])
			out[gid] = p[0]
		}
	}
	return out, nil
}
func command(ctx context.Context, input string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 1024 {
			output = output[:1024]
		}
		return fmt.Errorf("%s: %w: %s", filepath.Base(name), err, strings.TrimSpace(string(output)))
	}
	return nil
}
func Validate(s synchronization.Snapshot) error {
	if s.CertificatePolicy.Version != 0 && !s.CertificatePolicy.Valid() {
		return errors.New("invalid signed certificate policy")
	}
	if (s.Schema != 1 && s.Schema != 2 && s.Schema != 3) || s.NodeID == "" || s.Epoch == "" || s.Revision < 1 || len(s.Accounts) > 20000 {
		return errors.New("invalid snapshot manifest")
	}
	if err := s.Label.Validate(); err != nil {
		return err
	}
	groupNames := map[string]bool{}
	groupIDs := map[int]bool{}
	if len(s.Groups) > 10000 {
		return errors.New("too many UNIX groups")
	}
	for _, g := range s.Groups {
		if err := identity.ValidateGroup(g.Name, g.GID); err != nil {
			return err
		}
		if groupNames[g.Name] || groupIDs[g.GID] {
			return errors.New("duplicate UNIX group")
		}
		groupNames[g.Name] = true
		groupIDs[g.GID] = true
	}
	ids := map[string]bool{}
	logins := map[string]bool{}
	uids := map[int]bool{}
	for _, a := range s.Accounts {
		if err := a.Clearance.Validate(); err != nil {
			return err
		}
		if a.Enabled && !a.Clearance.Dominates(s.Label) {
			return errors.New("mandatory clearance does not permit node access")
		}
		if err := a.User.Validate(); err != nil {
			return err
		}
		if ids[a.User.ID] || logins[a.User.Login] || uids[a.User.UID] {
			return errors.New("duplicate account identity")
		}
		ids[a.User.ID] = true
		logins[a.User.Login] = true
		uids[a.User.UID] = true
		if s.Schema >= 3 && ((a.Enabled && (!a.User.SyncToNodes || (!a.AllowPassword && !a.AllowSSHKeys))) || (!a.AllowPassword && a.PasswordHash != "") || (!a.AllowSSHKeys && len(a.Keys) > 0)) {
			return errors.New("credentials violate explicit node login policy")
		}
		if !a.Enabled && (a.PasswordHash != "" || len(a.Keys) > 0 || len(a.Sudo) > 0 || len(a.Sudoers) > 0 || len(a.Groups) > 0) {
			return errors.New("disabled account contains credentials")
		}
		if a.PasswordHash != "" && (!strings.HasPrefix(a.PasswordHash, "$6$") || strings.ContainsAny(a.PasswordHash, "\n\r:\x00")) {
			return errors.New("unsupported account password hash")
		}
		seenGroups := map[string]bool{}
		for _, name := range a.Groups {
			if seenGroups[name] {
				return errors.New("duplicate supplementary group")
			}
			seenGroups[name] = true
			if !groupNames[name] {
				return errors.New("supplementary group missing from manifest")
			}
		}
		for _, k := range a.Keys {
			canonical, fp, alg, err := credentials.Parse(k.PublicKey, false)
			if err != nil || canonical != k.PublicKey || fp != k.Fingerprint || alg != k.Algorithm || k.UserID != a.User.ID {
				return errors.New("invalid snapshot key")
			}
		}
		if err := (authorization.Role{Name: "snapshot", LinuxAccess: true, Sudo: a.Sudo, Sudoers: strings.Join(a.Sudoers, "\n")}).Validate(); err != nil {
			return err
		}
	}
	return nil
}
func KeyFile(a synchronization.Account) string {
	var b strings.Builder
	for _, k := range a.Keys {
		if k.Status != "active" || !k.ExpiresAt.After(time.Now()) {
			continue
		}
		options := `expiry-time="` + k.ExpiresAt.UTC().Format("20060102150405Z") + `"`
		if strings.HasPrefix(k.Algorithm, "sk-") {
			options += ",verify-required"
		}
		b.WriteString(options + " " + k.PublicKey + "\n")
	}
	return b.String()
}
func SudoFile(a synchronization.Account) string {
	seen := map[string]bool{}
	lines := []string{}
	for _, r := range a.Sudo {
		password := "PASSWD"
		if r.NoPassword {
			password = "NOPASSWD"
		}
		command := r.Command
		if len(r.Arguments) > 0 {
			command += " " + strings.Join(r.Arguments, " ")
		} else {
			command += ` ""`
		}
		line := fmt.Sprintf("%s ALL=(%s) %s: %s", a.User.Login, r.RunAs, password, command)
		if !seen[line] {
			seen[line] = true
			lines = append(lines, line)
		}
	}
	for _, text := range a.Sudoers {
		for _, rhs := range strings.Split(text, "\n") {
			rhs = strings.TrimSpace(rhs)
			if rhs == "" {
				continue
			}
			line := a.User.Login + " " + rhs
			if !seen[line] {
				seen[line] = true
				lines = append(lines, line)
			}
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}
func (e *Executor) Apply(ctx context.Context, state synchronization.Snapshot, digest string) (synchronization.ApplyResult, error) {
	start := time.Now()
	result := synchronization.ApplyResult{Revision: state.Revision, Digest: digest, Results: []synchronization.ResourceResult{}}
	if err := Validate(state); err != nil {
		return result, err
	}
	checkpoint, err := e.Checkpoint()
	if err != nil {
		return result, err
	}
	if checkpoint.NodeID != "" && (checkpoint.NodeID != state.NodeID || checkpoint.Epoch != state.Epoch) {
		return result, errors.New("node identity or epoch mismatch; explicit recovery required")
	}
	if !state.Full && checkpoint.Revision != state.BaseRevision {
		return result, errors.New("delta base does not match durable checkpoint; full resynchronization required")
	}
	if state.Full {
		seen := map[string]bool{}
		for _, a := range state.Accounts {
			seen[a.User.ID] = true
		}
		for id := range checkpoint.Users {
			if !seen[id] {
				return result, errors.New("full snapshot omits managed account")
			}
		}
	}
	if state.Revision < checkpoint.Revision {
		return result, errors.New("refusing rollback")
	}
	local, uidNames, err := accounts()
	if err != nil {
		return result, err
	}
	groupNames, err := groups()
	if err != nil {
		return result, err
	}
	desired, err := json.Marshal(journal{State: state, Digest: digest})
	if err != nil {
		return result, err
	}
	if err = AtomicWrite(filepath.Join(e.StateDir, "pending.json"), desired, 0600); err != nil {
		return result, err
	}
	e.memberships, err = groupMemberships()
	if err != nil {
		return result, err
	}
	defer func() { e.memberships = nil }()
	e.revocations = newSessionRevocations(e.StateDir)
	defer func() { e.revocations = nil }()
	if policyErr := e.applySSHPolicy(ctx, state, local); policyErr != nil {
		// Do not grant access with an unenforced SSH policy. Revocations still
		// remove credentials and lock owned accounts despite an sshd failure.
		result.Error = "OpenSSH policy was not applied: " + policyErr.Error()
		for _, a := range state.Accounts {
			denied := synchronization.Account{User: a.User, Clearance: a.Clearance}
			cleanupErr := e.applyAccount(ctx, denied, local, uidNames, groupNames)
			message := result.Error
			if cleanupErr != nil {
				message += "; account quarantine: " + cleanupErr.Error()
			}
			result.Results = append(result.Results, synchronization.ResourceResult{UserID: a.User.ID, Login: a.User.Login, Status: "failed", Error: message})
		}
		e.finishRevocations(ctx, &result)
		result.Duration = time.Since(start).Seconds()
		return result, nil
	}
	groupErrors := map[int]error{}
	groupNameErrors := map[string]error{}
	for _, g := range state.Groups {
		if err = e.applyNamedGroup(ctx, g, groupNames); err != nil {
			groupErrors[g.GID] = err
			groupNameErrors[g.Name] = err
		}
	}
	next := Checkpoint{NodeID: state.NodeID, Epoch: state.Epoch, Revision: state.Revision, Digest: digest, Users: map[string]identity.User{}}
	if !state.Full {
		for id, u := range checkpoint.Users {
			next.Users[id] = u
		}
	}
	e.sudoError = e.validateSudoBatch(ctx, state.Accounts, checkpoint.Users)
	defer func() { e.sudoError = nil }()
	for _, a := range state.Accounts {
		r := synchronization.ResourceResult{UserID: a.User.ID, Login: a.User.Login, Status: "applied"}
		previous := checkpoint.Users[a.User.ID]
		if previous.ID != "" && (previous.Login != a.User.Login || previous.UID != a.User.UID || previous.GID != a.User.GID || previous.Home != a.User.Home) {
			err = e.migrate(ctx, a, previous, local, uidNames, groupNames)
		} else {
			err = nil
		}
		if err == nil && a.Enabled {
			err = groupErrors[a.User.GID]
			for _, name := range a.Groups {
				if groupNameErrors[name] != nil {
					err = groupNameErrors[name]
				}
			}
		}
		if err == nil {
			err = e.applyAccount(ctx, a, local, uidNames, groupNames)
		}
		if err != nil {
			r.Status = "failed"
			r.Error = err.Error()
			result.Error = "one or more Linux resources failed"
		} else {
			next.Users[a.User.ID] = a.User
		}
		result.Results = append(result.Results, r)
	}
	e.finishRevocations(ctx, &result)
	result.Duration = time.Since(start).Seconds()
	if result.Error == "" {
		if err = e.cache(state, digest); err != nil {
			return result, err
		}
		encoded, _ := json.Marshal(next)
		if err = AtomicWrite(filepath.Join(e.StateDir, "checkpoint.json"), encoded, 0600); err != nil {
			return result, err
		}
		if err = os.Remove(filepath.Join(e.StateDir, "pending.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
	}
	return result, nil
}
func (e *Executor) applyAccount(ctx context.Context, a synchronization.Account, local map[string]localAccount, uidNames map[int]string, groupNames map[int]string) error {
	u := a.User
	if err := validateHomeBase(u.Home); err != nil {
		return err
	}
	ownerPath := filepath.Join(managedDirectory, "users", u.Login+".json")
	existing, exists := local[u.Login]
	if exists {
		metadata, err := os.ReadFile(ownerPath)
		if err != nil {
			return errors.New("existing account is not managed by Heimdall")
		}
		var owner identity.User
		if json.Unmarshal(metadata, &owner) != nil || owner.ID != u.ID {
			return errors.New("managed ownership mismatch")
		}
		if existing.UID != u.UID || existing.GID != u.GID || existing.Home != u.Home {
			return errors.New("POSIX migration requires maintenance")
		}
		// Capture sessions before removing credentials. Repeated disabled states
		// also enforce process absence, including after an interrupted apply.
		if !a.Enabled && e.revocations != nil {
			if err := e.revocations.add(ctx, u); err != nil {
				e.revocations.errors[u.ID] = err
			}
		}
	}
	if !exists {
		if !a.Enabled {
			return nil
		}
		if name := uidNames[u.UID]; name != "" {
			return errors.New("UID already belongs to another account")
		}
		if err := e.managedGroup(ctx, u, groupNames); err != nil {
			return err
		}
		if info, err := os.Lstat(u.Home); err == nil {
			metadata, e := os.ReadFile(ownerPath)
			var prior identity.User
			stat, ok := info.Sys().(*syscall.Stat_t)
			if e != nil || json.Unmarshal(metadata, &prior) != nil || prior.ID != u.ID || !info.IsDir() || !ok || stat.Uid != uint32(u.UID) {
				return errors.New("home already exists and is not an interrupted managed creation")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}

		// Record ownership before useradd so recovery can recognise a crash after creation.
		meta, _ := json.Marshal(u)
		if err := AtomicWrite(ownerPath, meta, 0600); err != nil {
			return err
		}
		if err := createUser(ctx, u); err != nil {
			return err
		}
		local[u.Login] = localAccount{UID: u.UID, GID: u.GID, Home: u.Home}
		uidNames[u.UID] = u.Login
	}
	if exists && matches(a, existing) && sameGroups(e.memberships[u.Login], a.Groups) {
		return nil
	}
	if err := quarantineUser(ctx, u.Login); err != nil {
		return err
	}
	keys := ""
	if a.Enabled {
		keys = KeyFile(a)
	}
	if err := AtomicWrite(filepath.Join(managedDirectory, "authorized_keys", u.Login), []byte(keys), 0644); err != nil {
		return err
	}
	if err := e.sudo(ctx, a); err != nil {
		return err
	}
	if !sameGroups(e.memberships[u.Login], a.Groups) {
		if err := setGroups(ctx, u.Login, a.Groups); err != nil {
			return err
		}
		e.memberships[u.Login] = a.Groups
	}
	if err := setPassword(ctx, u.Login, "*"); err != nil {
		return err
	}
	if a.Enabled && a.PasswordHash != "" {
		if err := setPassword(ctx, u.Login, a.PasswordHash); err != nil {
			return err
		}
	}
	shell := "/usr/sbin/nologin"
	expire := "1970-01-02"
	if a.Enabled {
		shell = u.Shell
		expire = ""
	}
	if err := activateUser(ctx, u.Login, nativeShell(shell), u.GECOS, expire == ""); err != nil {
		return err
	}
	metadata, _ := json.Marshal(u)
	return AtomicWrite(ownerPath, metadata, 0600)
}
func sudoContent(a synchronization.Account) []byte {
	content := []byte("# Managed by Heimdall\n")
	if a.Enabled && (len(a.Sudo) > 0 || len(a.Sudoers) > 0) {
		content = append(content, []byte(SudoFile(a))...)
	}
	return content
}
func (e *Executor) sudo(_ context.Context, a synchronization.Account) error {
	if a.Enabled && (len(a.Sudo) > 0 || len(a.Sudoers) > 0) && e.sudoError != nil {
		return e.sudoError
	}
	return AtomicWrite(filepath.Join(sudoDirectory, sudoPrefix()+a.User.Login), sudoContent(a), 0440)
}
func (e *Executor) validateSudoBatch(ctx context.Context, accounts []synchronization.Account, prior map[string]identity.User) error {
	replacements := map[string][]byte{}
	stage := func(account synchronization.Account) {
		file := sudoPrefix() + account.User.Login
		content := sudoContent(account)
		info, err := os.Lstat(filepath.Join(sudoDirectory, file))
		if err == nil && info.Mode().IsRegular() {
			raw, err := os.ReadFile(filepath.Join(sudoDirectory, file))
			if err == nil && bytes.Equal(raw, content) {
				return
			}
		}
		replacements[file] = content
	}
	for _, a := range accounts {
		stage(a)
		if old := prior[a.User.ID]; old.ID != "" && old.Login != a.User.Login {
			stage(synchronization.Account{User: old})
		}
	}
	if len(replacements) == 0 {
		return nil
	}
	temp, err := os.MkdirTemp(e.StateDir, "sudo-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	include := filepath.Join(temp, "includes")
	if err = os.Mkdir(include, 0750); err != nil {
		return err
	}
	entries, err := os.ReadDir(sudoDirectory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || replacements[entry.Name()] != nil || strings.Contains(entry.Name(), ".") {
			continue
		}
		info, err := os.Lstat(filepath.Join(sudoDirectory, entry.Name()))
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("unsafe sudo include")
		}
		data, err := os.ReadFile(filepath.Join(sudoDirectory, entry.Name()))
		if err != nil {
			return err
		}
		if err = AtomicWrite(filepath.Join(include, entry.Name()), data, 0440); err != nil {
			return err
		}
	}
	for file, content := range replacements {
		if err = AtomicWrite(filepath.Join(include, file), content, 0440); err != nil {
			return err
		}
	}
	main, err := os.ReadFile(sudoMainFile)
	if err != nil {
		return err
	}
	text := strings.ReplaceAll(string(main), "@includedir "+sudoDirectory, "@includedir "+include)
	text = strings.ReplaceAll(text, "#includedir "+sudoDirectory, "#includedir "+include)
	if !strings.Contains(text, include) {
		text += "\n@includedir " + include + "\n"
	}
	candidate := filepath.Join(temp, "sudoers")
	if err = AtomicWrite(candidate, []byte(text), 0440); err != nil {
		return err
	}
	if err = command(ctx, "", visudoBinary, "-c", "-s", "-O", "-P", "-f", candidate); err != nil {
		return err
	}
	return nil
}
