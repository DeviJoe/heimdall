//go:build linux

package native

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func nativeBootIdentity() (string, error) {
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b)), e
}
func readLinuxProcess(pid int) (nativeProcess, error) {
	p := nativeProcess{PID: pid}
	base := "/proc/" + strconv.Itoa(pid)
	stat, err := os.ReadFile(base + "/stat")
	if err != nil {
		return p, err
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return p, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return p, errors.New("truncated process stat")
	}
	p.Parent, err = strconv.Atoi(fields[1])
	if err != nil {
		return p, err
	}
	p.Start = fields[19]
	p.Zombie = fields[0] == "Z" || fields[0] == "X"
	status, err := os.ReadFile(base + "/status")
	if err != nil {
		return p, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			for _, v := range strings.Fields(line)[1:] {
				uid, e := strconv.Atoi(v)
				if e != nil {
					return p, e
				}
				p.UIDs = append(p.UIDs, uid)
			}
		}
	}
	if len(p.UIDs) == 0 {
		return p, errors.New("process UID missing")
	}
	// Audit loginuid preserves attribution after sudo changes all UID fields.
	if data, e := os.ReadFile(base + "/loginuid"); e == nil {
		if uid, e := strconv.Atoi(strings.TrimSpace(string(data))); e == nil && uid >= 10000 && uid <= 2147483646 {
			p.UIDs = append(p.UIDs, uid)
		}
	}
	if exe, e := os.Readlink(base + "/exe"); e == nil {
		p.Executable = filepath.Base(exe)
		if p.Executable == "sshd" || p.Executable == "sshd-session" {
			data, e := os.ReadFile(base + "/cmdline")
			if e != nil {
				return p, e
			}
			p.Command = strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
		}
	}
	// Detect an exit/reuse during collection as well as before signalling.
	after, e := os.ReadFile(base + "/stat")
	if e != nil {
		return p, e
	}
	tail := strings.LastIndexByte(string(after), ')')
	if tail < 0 {
		return p, syscall.ESRCH
	}
	f := strings.Fields(string(after[tail+1:]))
	if len(f) < 20 || f[19] != p.Start {
		return p, syscall.ESRCH
	}
	return p, nil
}
func listNativeProcesses(ctx context.Context) ([]nativeProcess, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := []nativeProcess{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid <= 1 {
			continue
		}
		p, e := readLinuxProcess(pid)
		if errors.Is(e, os.ErrNotExist) || errors.Is(e, syscall.ESRCH) {
			continue
		}
		if e != nil {
			return nil, fmt.Errorf("inspect PID %d: %w", pid, e)
		}
		out = append(out, p)
	}
	return out, nil
}
func signalNativeProcess(ctx context.Context, target processTarget, signal syscall.Signal) error {
	if target.PID <= 1 || target.PID == os.Getpid() {
		return errors.New("protected process")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.PidfdOpen(target.PID, 0)
	if err != nil {
		return err
	} // No PID-only fallback on old kernels.
	defer unix.Close(fd)
	p, err := readLinuxProcess(target.PID)
	if errors.Is(err, os.ErrNotExist) {
		return syscall.ESRCH
	}
	if err != nil {
		return err
	}
	if p.Start != target.Start || p.Zombie {
		return syscall.ESRCH
	}
	return unix.PidfdSendSignal(fd, unix.Signal(signal), nil, 0)
}
