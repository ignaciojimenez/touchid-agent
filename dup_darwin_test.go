//go:build darwin

package main

import "golang.org/x/sys/unix"

func dupSyscall(fd int) (int, error) {
	return unix.Dup(fd)
}
