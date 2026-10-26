package native

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func nativeBootIdentity() (string, error) {
	t, e := unix.SysctlTimeval("kern.boottime")
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%d:%d", t.Sec, t.Usec), nil
}
func listNativeProcesses(ctx context.Context) ([]nativeProcess, error) {
	return freeBSDProcesses(ctx, 0)
}
func freeBSDProcesses(ctx context.Context, pid int) ([]nativeProcess, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	args := []string{"-axww"}
	if pid > 0 {
		args = []string{"-p", strconv.Itoa(pid), "-ww"}
	}
	args = append(args, "-o", "pid=,ppid=,ruid=,uid=,lstart=,stat=,comm=,args=")
	cmd := exec.CommandContext(ctx, "/bin/ps", args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/bin:/usr/bin"}
	data, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if pid > 0 && len(data) == 0 && ctx.Err() == nil && errors.As(err, &exit) && exit.ExitCode() == 1 {
			return nil, nil // Target exited before its identity could be read.
		}
		return nil, err
	}
	return parseFreeBSDProcesses(string(data))
}
func parseFreeBSDProcesses(data string) ([]nativeProcess, error) {
	out := []nativeProcess{}
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 11 {
			return nil, errors.New("truncated FreeBSD process record")
		}
		pid, e := strconv.Atoi(f[0])
		if e != nil {
			return nil, e
		}
		parent, e := strconv.Atoi(f[1])
		if e != nil {
			return nil, e
		}
		real, e := strconv.Atoi(f[2])
		if e != nil {
			return nil, e
		}
		effective, e := strconv.Atoi(f[3])
		if e != nil {
			return nil, e
		}
		out = append(out, nativeProcess{PID: pid, Parent: parent, UIDs: []int{real, effective}, Start: strings.Join(f[4:9], " "), Zombie: strings.Contains(f[9], "Z"), Executable: filepath.Base(f[10]), Command: strings.Join(f[11:], " ")})
	}
	return out, nil
}
func signalNativeProcess(ctx context.Context, target processTarget, signal syscall.Signal) error {
	if target.PID <= 1 || target.PID == os.Getpid() {
		return errors.New("protected process")
	}
	// FreeBSD has no Linux pidfd for arbitrary existing processes. Revalidate
	// creation time immediately before kill, never signal a process group.
	ps, err := freeBSDProcesses(ctx, target.PID)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if p.PID == target.PID && p.Start == target.Start && !p.Zombie {
			return syscall.Kill(p.PID, signal)
		}
	}
	return syscall.ESRCH
}
