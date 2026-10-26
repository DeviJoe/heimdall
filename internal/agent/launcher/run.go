package launcher

import (
	"Heimdall/internal/agent/client"
	"Heimdall/internal/agent/helper"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func Network(ctx context.Context, c Config) error {
	if c.Recover {
		return client.Recover(ctx, c.Client())
	}
	return client.Run(ctx, c.Client())
}
func InternalNetwork(ctx context.Context) error {
	if os.Geteuid() == 0 {
		return errors.New("network subprocess must not run as root")
	}
	pipe := os.NewFile(3, "agent-configuration")
	if pipe == nil {
		return errors.New("configuration pipe required")
	}
	defer pipe.Close()
	var c Config
	decoder := json.NewDecoder(pipe)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return errors.New("invalid internal configuration")
	}
	return Network(ctx, c)
}
func Run(ctx context.Context, c Config) error {
	if os.Geteuid() != 0 {
		return Network(ctx, c)
	} // Compatibility with managed service supervisors.
	account, err := user.Lookup(c.RunAs)
	if err != nil {
		return fmt.Errorf("install the dedicated %s service account before starting the agent: %w", c.RunAs, err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid <= 0 || uid >= 10000 {
		return errors.New("network process requires a dedicated system UID in 1..9999")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid <= 0 {
		return errors.New("network process requires an unprivileged GID")
	}
	for _, dir := range []string{c.StateDir, c.WorkerStateDir, filepath.Dir(c.Socket)} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe agent directory")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && !(dir == c.StateDir && stat.Uid == uint32(uid))) || info.Mode().Perm()&0022 != 0 {
			return errors.New("agent directory has unsafe ownership")
		}
	}
	if err = os.Chown(c.StateDir, uid, gid); err != nil {
		return err
	}
	if err = os.Chmod(c.StateDir, 0700); err != nil {
		return err
	}
	if err = os.Chmod(c.WorkerStateDir, 0700); err != nil {
		return err
	}
	// A fresh runtime directory starts private. Grant only traversal to the
	// network service group; the child still cannot replace the root socket.
	if err = os.Chown(filepath.Dir(c.Socket), 0, gid); err != nil {
		return err
	}
	if err = os.Chmod(filepath.Dir(c.Socket), 0710); err != nil {
		return err
	}
	// The worker is the root supervisor. Only the child makes network calls;
	// its inherited environment contains no enrollment or recovery secrets.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	worker := make(chan error, 1)
	go func() {
		worker <- helper.ServeWithIdentity(ctx, c.Socket, c.WorkerStateDir, c.StateKey, c.AuthLog, c.JoinToken, uid, gid)
	}()
	ready := helper.Client(c.Socket)
	ready.Timeout = 2 * time.Second
	deadline := time.Now().Add(time.Minute)
	for {
		request, _ := http.NewRequestWithContext(ctx, "GET", "http://helper/bootstrap", nil)
		response, err := ready.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		select {
		case err := <-worker:
			return err
		case <-ctx.Done():
			return nil
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("privileged worker startup timed out")
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	for {
		read, write, err := os.Pipe()
		if err != nil {
			return err
		}
		child := exec.CommandContext(ctx, executable, "--internal-client")
		child.ExtraFiles = []*os.File{read}
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if key != "HEIMDALL_JOIN_TOKEN" && key != "HEIMDALL_RECOVERY_TOKEN" && key != "HEIMDALL_AGENT_CONFIG" {
				child.Env = append(child.Env, entry)
			}
		}
		child.Cancel = func() error { return child.Process.Signal(syscall.SIGTERM) }
		child.WaitDelay = 5 * time.Second
		if err = child.Start(); err != nil {
			read.Close()
			write.Close()
			return err
		}
		read.Close()
		if err = json.NewEncoder(write).Encode(c); err != nil {
			write.Close()
			child.Process.Kill()
			child.Wait()
			return err
		}
		write.Close()
		done := make(chan error, 1)
		go func() { done <- child.Wait() }()
		select {
		case err := <-worker:
			cancel()
			<-done
			return err
		case <-ctx.Done():
			cancel()
			<-done
			return nil
		case err := <-done:
			if c.Recover {
				return err
			}
			slog.Warn("network agent exited; restarting", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-worker:
			return err
		case <-time.After(time.Duration(5+mathrand.IntN(10)) * time.Second):
		}
	}
}
