//go:build !linux && !freebsd

package native

import (
	"context"
	"errors"
	"syscall"
)

func nativeBootIdentity() (string, error) {
	return "", errors.New("native session revocation requires Linux or FreeBSD")
}
func listNativeProcesses(context.Context) ([]nativeProcess, error) {
	return nil, errors.New("native process inspection requires Linux or FreeBSD")
}
func signalNativeProcess(context.Context, processTarget, syscall.Signal) error {
	return errors.New("native process signalling requires Linux or FreeBSD")
}
