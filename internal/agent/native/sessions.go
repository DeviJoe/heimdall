package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"Heimdall/internal/identity"
	"Heimdall/internal/synchronization"
)

// Process identities are persisted before signalling: a root sudo descendant
// must remain a target even if its parent exits or the agent restarts.
type nativeProcess struct {
	PID, Parent                int
	UIDs                       []int
	Start, Command, Executable string
	Zombie                     bool
}
type processTarget struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
}
type revocationPlan struct {
	User    identity.User   `json:"user"`
	Boot    string          `json:"boot"`
	Targets []processTarget `json:"targets"`
}
type processIndex struct {
	processes map[int]nativeProcess
	byUID     map[int][]int
	children  map[int][]int
	monitors  map[string][]int
}

func indexProcesses(processes []nativeProcess) processIndex {
	idx := processIndex{map[int]nativeProcess{}, map[int][]int{}, map[int][]int{}, map[string][]int{}}
	for _, p := range processes {
		if p.PID <= 1 || p.PID == os.Getpid() || p.Zombie {
			continue
		}
		idx.processes[p.PID] = p
		idx.children[p.Parent] = append(idx.children[p.Parent], p.PID)
		for _, uid := range p.UIDs {
			idx.byUID[uid] = append(idx.byUID[uid], p.PID)
		}
		if len(p.UIDs) > 0 && p.UIDs[0] == 0 && (p.Executable == "sshd" || p.Executable == "sshd-session") {
			// Only authenticated per-user monitors, never the listener or preauth.
			for _, prefix := range []string{"sshd: ", "sshd-session: "} {
				if len(p.Command) > len(prefix) && p.Command[:len(prefix)] == prefix {
					name := p.Command[len(prefix):]
					const suffix = " [priv]"
					if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
						idx.monitors[name[:len(name)-len(suffix)]] = append(idx.monitors[name[:len(name)-len(suffix)]], p.PID)
					}
				}
			}
		}
	}
	return idx
}
func (idx processIndex) targets(u identity.User, prior []processTarget) []processTarget {
	seen := map[int]bool{}
	queue := append(append([]int{}, idx.byUID[u.UID]...), idx.monitors[u.Login]...)
	for _, target := range prior {
		if p, ok := idx.processes[target.PID]; ok && p.Start == target.Start {
			queue = append(queue, p.PID)
		}
	}
	out := []processTarget{}
	for head := 0; head < len(queue); head++ {
		pid := queue[head]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		p, ok := idx.processes[pid]
		if !ok {
			continue
		}
		out = append(out, processTarget{pid, p.Start})
		queue = append(queue, idx.children[pid]...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

type sessionRevocations struct {
	directory string
	plans     map[string]revocationPlan
	index     *processIndex
	boot      string
	errors    map[string]error
}

func newSessionRevocations(stateDir string) *sessionRevocations {
	return &sessionRevocations{directory: filepath.Join(stateDir, "revocations"), plans: map[string]revocationPlan{}, errors: map[string]error{}}
}
func (r *sessionRevocations) snapshot(ctx context.Context) error {
	ps, err := listNativeProcesses(ctx)
	if err != nil {
		return err
	}
	idx := indexProcesses(ps)
	r.index = &idx
	return nil
}
func (r *sessionRevocations) save(id string, plan revocationPlan) error {
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(r.directory, id+".json"), data, 0600)
}
func (r *sessionRevocations) add(ctx context.Context, u identity.User) error {
	if err := u.Validate(); err != nil {
		return err
	}
	if _, err := uuid.Parse(u.ID); err != nil {
		return errors.New("invalid revocation owner ID")
	}
	if r.index == nil {
		var err error
		r.boot, err = nativeBootIdentity()
		if err != nil {
			return err
		}
		if err = os.MkdirAll(r.directory, 0700); err != nil {
			return err
		}
		info, err := os.Lstat(r.directory)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("unsafe revocation journal directory")
		}
		if err = r.snapshot(ctx); err != nil {
			return err
		}
	}
	plan := revocationPlan{User: u, Boot: r.boot}
	path := filepath.Join(r.directory, u.ID+".json")
	data, err := os.ReadFile(path)
	if err == nil {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("unsafe revocation journal")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("unsafe revocation journal owner")
		}
		var old revocationPlan
		if json.Unmarshal(data, &old) != nil || old.User.ID != u.ID || old.User.UID != u.UID {
			return errors.New("revocation journal identity mismatch")
		}
		if old.Boot == r.boot {
			plan.Targets = old.Targets
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	plan.Targets = r.index.targets(u, plan.Targets)
	r.plans[u.ID] = plan
	if len(plan.Targets) > 0 {
		return r.save(u.ID, plan)
	}
	return nil
}
func (r *sessionRevocations) finish(ctx context.Context) map[string]error {
	failures := map[string]error{}
	for id, err := range r.errors {
		failures[id] = err
	}
	if len(r.plans) == 0 {
		return failures
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// A single process scan per round, independent of the number of disabled users.
	for round := 0; round < 4; round++ {
		if err := r.snapshot(ctx); err != nil {
			for id := range r.plans {
				failures[id] = err
			}
			return failures
		}
		pending := false
		for id, plan := range r.plans {
			plan.Targets = r.index.targets(plan.User, plan.Targets)
			r.plans[id] = plan
			if len(plan.Targets) == 0 {
				if err := os.Remove(filepath.Join(r.directory, id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
					failures[id] = err
				} else {
					delete(r.plans, id)
				}
				continue
			}
			pending = true
			if err := r.save(id, plan); err != nil {
				failures[id] = err
				continue
			}
			signal := syscall.SIGKILL
			if round == 0 {
				signal = syscall.SIGTERM
			}
			for _, target := range plan.Targets {
				if err := signalNativeProcess(ctx, target, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
					failures[id] = fmt.Errorf("terminate PID %d: %w", target.PID, err)
				}
			}
		}
		if !pending {
			return failures
		}
		timer := time.NewTimer(300 * time.Millisecond)
		if round == 0 {
			timer.Reset(1500 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			for id := range r.plans {
				failures[id] = ctx.Err()
			}
			return failures
		case <-timer.C:
		}
	}
	if err := r.snapshot(ctx); err != nil {
		for id := range r.plans {
			failures[id] = err
		}
		return failures
	}
	for id, plan := range r.plans {
		if len(r.index.targets(plan.User, plan.Targets)) > 0 {
			failures[id] = errors.New("user sessions or processes are still running; revocation remains pending")
		} else {
			if err := os.Remove(filepath.Join(r.directory, id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
				failures[id] = err
			} else {
				delete(r.plans, id)
			}
		}
	}
	return failures
}
func (e *Executor) finishRevocations(ctx context.Context, result *synchronization.ApplyResult) {
	if e.revocations == nil {
		return
	}
	failures := e.revocations.finish(ctx)
	for i := range result.Results {
		row := &result.Results[i]
		if err := failures[row.UserID]; err != nil {
			row.Status = "failed"
			if row.Error != "" {
				row.Error += "; "
			}
			row.Error += "session revocation: " + err.Error()
			result.Error = "one or more account revocations are incomplete"
		}
	}
}
