//go:build darwin

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCreds returns the PID and UID of the process on the other end of
// a Unix-domain socket connection. Returns a zero Peer if the connection
// is not a Unix socket or if the syscalls fail; a zero Peer is safe to
// pass to AuditLogger.Sign.
func peerCreds(c net.Conn) Peer {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}
	}
	var p Peer
	raw.Control(func(fd uintptr) {
		if pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			p.PID = pid
		}
		if cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED); err == nil {
			p.UID = cred.Uid
		}
	})
	return p
}
