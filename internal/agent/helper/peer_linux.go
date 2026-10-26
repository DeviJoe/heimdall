//go:build linux

package helper

import (
	"golang.org/x/sys/unix"
	"net"
)

func peerAllowed(conn net.Conn, uid int) bool {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	allowed := false
	raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		allowed = e == nil && (int(cred.Uid) == uid || cred.Uid == 0)
	})
	return allowed
}
