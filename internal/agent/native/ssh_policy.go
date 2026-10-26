package native

import (
	"Heimdall/internal/synchronization"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Policies live in root-owned OpenSSH configuration. SSH needs neither the
// helper nor the agent running. Native passwords are independently locked too.
func SSHPolicy(accounts []synchronization.Account) string {
	sorted := append([]synchronization.Account(nil), accounts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].User.Login < sorted[j].User.Login })
	var out strings.Builder
	out.WriteString("# Managed by Heimdall; explicit node login methods\n")
	for _, a := range sorted {
		password, keys := "no", "no"
		methods := []string{}
		if a.Enabled && a.AllowPassword {
			password = "yes"
			methods = append(methods, "password")
		}
		if a.Enabled && a.AllowSSHKeys {
			keys = "yes"
			methods = append(methods, "publickey")
		}
		// OpenSSH 9.2 reparses even inactive Match clauses and rejects "any"
		// after a nonempty method list. Disabled accounts need no override:
		// every authentication backend is off and the native account is expired.
		authentication := ""
		if len(methods) > 0 {
			authentication = strings.Join(methods, " ")
		}
		fmt.Fprintf(&out, "Match User %s\n PasswordAuthentication %s\n PubkeyAuthentication %s\n", a.User.Login, password, keys)
		if authentication != "" {
			fmt.Fprintf(&out, " AuthenticationMethods %s\n", authentication)
		}
		fmt.Fprintf(&out, " KbdInteractiveAuthentication no\n HostbasedAuthentication no\n GSSAPIAuthentication no\n PermitEmptyPasswords no\n AuthorizedKeysFile %s/authorized_keys/%%u\n AuthorizedKeysCommand none\n TrustedUserCAKeys none\n", managedDirectory)
	}
	out.WriteString("Match all\n")
	return out.String()
}

// A Match block cannot precede global-only directives such as Port. Insert the
// managed include after globals and before existing conditional blocks.
func sshConfigWithPolicy(config, policyPath string) (string, error) {
	anchor := "Include " + managedDirectory + "/sshd_config"
	lines := []string{}
	for _, line := range strings.Split(config, "\n") {
		if strings.TrimSpace(line) != anchor {
			lines = append(lines, line)
		}
	}
	position := len(lines)
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], "Match") {
			position = i
			break
		}
	}
	if err := checkGlobalSSHIncludes(lines[:position], 0); err != nil {
		return "", err
	}
	prefix := strings.TrimRight(strings.Join(lines[:position], "\n"), "\n")
	suffix := strings.Trim(strings.Join(lines[position:], "\n"), "\n")
	if suffix != "" {
		suffix += "\n"
	}
	return prefix + "\nInclude " + policyPath + "\n" + suffix, nil
}

func checkGlobalSSHIncludes(lines []string, depth int) error {
	if depth > 10 {
		return errors.New("OpenSSH Include nesting limit exceeded")
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Include") {
			continue
		}
		for _, pattern := range fields[1:] {
			if strings.HasPrefix(pattern, "#") {
				break
			}
			pattern = strings.Trim(pattern, "\"")
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join("/etc/ssh", pattern)
			}
			files, err := filepath.Glob(pattern)
			if err != nil {
				return err
			}
			for _, file := range files {
				raw, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				nested := strings.Split(string(raw), "\n")
				for _, entry := range nested {
					f := strings.Fields(entry)
					if len(f) > 0 && strings.EqualFold(f[0], "Match") {
						return fmt.Errorf("OpenSSH conditional Include %s precedes Heimdall policy; move it below the managed Include", file)
					}
				}
				if err = checkGlobalSSHIncludes(nested, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (e *Executor) applySSHPolicy(ctx context.Context, state synchronization.Snapshot, local map[string]localAccount) error {
	if state.Schema < 3 {
		return nil
	}
	desired := state
	if !state.Full {
		previous, err := e.readJournal("desired.json")
		if err != nil {
			return err
		}
		desired, err = materializeDesired(previous.State, state)
		if err != nil {
			return err
		}
	}
	for _, a := range desired.Accounts {
		if _, exists := local[a.User.Login]; !exists {
			continue
		}
		var owner struct {
			ID string `json:"id"`
		}
		raw, err := os.ReadFile(filepath.Join(managedDirectory, "users", a.User.Login+".json"))
		if err != nil || json.Unmarshal(raw, &owner) != nil || owner.ID != a.User.ID {
			return errors.New("SSH policy refuses an unmanaged local account: " + a.User.Login)
		}
	}
	policyPath := managedDirectory + "/sshd_config"
	policy := []byte(SSHPolicy(desired.Accounts))
	configPath := "/etc/ssh/sshd_config"
	info, err := os.Lstat(configPath)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe OpenSSH configuration")
	}
	original, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	config, err := sshConfigWithPolicy(string(original), policyPath)
	if err != nil {
		return err
	}
	existing, err := os.ReadFile(policyPath)
	fingerprint := sha256.Sum256(append([]byte(config), policy...))
	marker := []byte(hex.EncodeToString(fingerprint[:]))
	applied, _ := os.ReadFile(filepath.Join(e.StateDir, "sshd-policy-applied"))
	if err == nil && bytes.Equal(existing, policy) && string(original) == config && bytes.Equal(applied, marker) {
		info, err := os.Lstat(policyPath)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid == 0 {
				return nil
			}
		}
	}
	temp, err := os.MkdirTemp(e.StateDir, "ssh-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	candidatePolicy := filepath.Join(temp, "policy")
	if err = AtomicWrite(candidatePolicy, policy, 0600); err != nil {
		return err
	}
	candidateConfig, err := sshConfigWithPolicy(string(original), candidatePolicy)
	if err != nil {
		return err
	}
	candidatePath := filepath.Join(temp, "sshd_config")
	if err = AtomicWrite(candidatePath, []byte(candidateConfig), 0600); err != nil {
		return err
	}
	if err = command(ctx, "", "/usr/sbin/sshd", "-t", "-f", candidatePath); err != nil {
		return fmt.Errorf("OpenSSH policy validation: %w", err)
	}
	// Syntax-only -t skips conditional semantics. Check one representative of
	// each of the four method combinations; never spawn O(users) sshd processes.
	checked := map[[2]bool]bool{}
	for _, a := range desired.Accounts {
		methods := [2]bool{a.Enabled && a.AllowPassword, a.Enabled && a.AllowSSHKeys}
		if checked[methods] {
			continue
		}
		checked[methods] = true
		if err = command(ctx, "", "/usr/sbin/sshd", "-T", "-f", candidatePath, "-C", "user="+a.User.Login+",host=localhost,addr=127.0.0.1"); err != nil {
			return fmt.Errorf("OpenSSH conditional policy validation: %w", err)
		}
	}
	if err = AtomicWrite(policyPath, policy, 0600); err != nil {
		return err
	}
	if err = AtomicWrite(configPath, []byte(config), info.Mode().Perm()); err != nil {
		return err
	}
	if err = reloadSSHD(ctx); err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(e.StateDir, "sshd-policy-applied"), marker, 0600)
}

func reloadSSHD(ctx context.Context) error {
	output, err := exec.CommandContext(ctx, "/usr/sbin/sshd", "-T").Output()
	if err != nil {
		return err
	}
	pidFile := ""
	for _, line := range strings.Split(string(output), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "pidfile" {
			pidFile = f[1]
		}
	}
	if !filepath.IsAbs(pidFile) {
		return errors.New("OpenSSH must use an absolute PidFile")
	}
	info, err := os.Lstat(pidFile)
	if err != nil {
		return fmt.Errorf("OpenSSH PidFile: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe OpenSSH PidFile")
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		return errors.New("invalid OpenSSH process ID")
	}
	if runtime.GOOS == "linux" {
		executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || filepath.Base(executable) != "sshd" {
			return errors.New("PidFile does not identify OpenSSH")
		}
	} else {
		comm, err := exec.CommandContext(ctx, "/bin/ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
		if err != nil || !strings.HasPrefix(filepath.Base(strings.TrimSpace(string(comm))), "sshd") {
			return errors.New("PidFile does not identify OpenSSH")
		}
	}
	return syscall.Kill(pid, syscall.SIGHUP)
}
