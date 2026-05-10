//go:build darwin

package main

/*
#include <libproc.h>
*/
import "C"

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Peer captures local socket peer credentials. Zero values mean the
// credentials could not be determined; they are still safe to log
// (omitempty drops them from the JSON record).
type Peer struct {
	PID  int
	UID  uint32
	Path string
}

// peerCreds returns the PID, UID, and binary path of the process on
// the other end of a Unix-domain socket connection. Returns a zero
// Peer if the connection is not a Unix socket or if the syscalls fail;
// a zero Peer is safe to pass to AuditLogger.Sign.
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
	if p.PID > 0 {
		p.Path = procPidPath(p.PID)
	}
	return p
}

func procPidPath(pid int) string {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if ret <= 0 {
		return ""
	}
	return string(buf[:ret])
}
