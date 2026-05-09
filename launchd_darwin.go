//go:build darwin

package main

/*
#include <launch.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"unsafe"
)

const launchdSocketName = "Listeners"

// launchdActivateSocket calls launch_activate_socket(3) to retrieve
// file descriptors for the named socket entry in the launchd plist.
func launchdActivateSocket(name string) ([]int, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	var fds *C.int
	var cnt C.size_t

	rc := C.launch_activate_socket(cName, &fds, &cnt)
	if rc != 0 {
		return nil, fmt.Errorf("launch_activate_socket(%q): errno %d", name, rc)
	}
	defer C.free(unsafe.Pointer(fds))

	result := make([]int, int(cnt))
	fdSlice := unsafe.Slice(fds, cnt)
	for i, fd := range fdSlice {
		result[i] = int(fd)
	}
	return result, nil
}

// launchdListener returns a net.Listener for the first socket fd
// obtained from launchd socket activation.
func launchdListener() (net.Listener, error) {
	fds, err := launchdActivateSocket(launchdSocketName)
	if err != nil {
		return nil, err
	}
	if len(fds) == 0 {
		return nil, fmt.Errorf("launchd returned no socket file descriptors")
	}

	f := os.NewFile(uintptr(fds[0]), "launchd-socket")
	if f == nil {
		return nil, fmt.Errorf("invalid file descriptor %d from launchd", fds[0])
	}
	defer f.Close()

	l, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("create listener from launchd fd: %w", err)
	}
	return l, nil
}
