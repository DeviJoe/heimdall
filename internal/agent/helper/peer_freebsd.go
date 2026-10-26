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
	if err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), 0, unix.LOCAL_PEERCRED)
		allowed = e == nil && (int(cred.Uid) == uid || cred.Uid == 0)
	}); err != nil {
		return false
	}
	return allowed
}
