//go:build !linux && !freebsd

package helper

import "net"

func peerAllowed(conn net.Conn, uid int) bool { return false }
