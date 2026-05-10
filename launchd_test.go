//go:build darwin

package main

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func launchdTestSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tid-ld-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return fmt.Sprintf("%s/s.sock", dir)
}

func TestFileListenerFromUnixSocket(t *testing.T) {
	sock := launchdTestSocket(t)

	// Create a Unix listener the normal way, extract its fd, then
	// reconstruct a listener from that fd -- the same path launchd
	// socket activation takes.
	orig, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	uc := orig.(*net.UnixListener)
	uc.SetUnlinkOnClose(false)

	rawConn, err := uc.SyscallConn()
	if err != nil {
		orig.Close()
		t.Fatal(err)
	}

	var fd int
	rawConn.Control(func(f uintptr) {
		fd = int(f)
	})

	dupFd, err := dupFD(fd)
	if err != nil {
		orig.Close()
		t.Fatal(err)
	}
	orig.Close()

	f := os.NewFile(uintptr(dupFd), "test-socket")
	if f == nil {
		t.Fatal("os.NewFile returned nil")
	}
	defer f.Close()

	l, err := net.FileListener(f)
	if err != nil {
		t.Fatalf("net.FileListener: %v", err)
	}
	defer l.Close()

	// Verify the reconstructed listener works: connect and exchange data.
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		buf := make([]byte, 5)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			done <- err
			return
		}
		if string(buf[:n]) != "hello" {
			done <- fmt.Errorf("got %q, want %q", buf[:n], "hello")
			return
		}
		done <- nil
	}()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("hello"))
	conn.Close()

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestIdleTimerExitsAcceptLoop(t *testing.T) {
	sock := launchdTestSocket(t)

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	idleTimeout := 200 * time.Millisecond
	idleTimer := time.AfterFunc(idleTimeout, func() {
		l.Close()
	})

	start := time.Now()
	var loopExited bool
	for {
		_, err := l.Accept()
		if err != nil {
			loopExited = true
			break
		}
	}
	elapsed := time.Since(start)

	if !loopExited {
		t.Fatal("accept loop should have exited")
	}
	if elapsed < idleTimeout {
		t.Errorf("exited too early: %v < %v", elapsed, idleTimeout)
	}
	if elapsed > 5*time.Second {
		t.Errorf("exited too late: %v", elapsed)
	}
	idleTimer.Stop()
}

func TestIdleTimerResetsOnConnection(t *testing.T) {
	sock := launchdTestSocket(t)

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	idleTimeout := 300 * time.Millisecond
	idleTimer := time.AfterFunc(idleTimeout, func() {
		l.Close()
	})

	// Connect twice, each time before the timer fires, to prove the
	// timer resets on activity.
	go func() {
		time.Sleep(150 * time.Millisecond)
		c, err := net.Dial("unix", sock)
		if err == nil {
			c.Close()
		}
		time.Sleep(150 * time.Millisecond)
		c, err = net.Dial("unix", sock)
		if err == nil {
			c.Close()
		}
	}()

	connections := 0
	for {
		conn, err := l.Accept()
		if err != nil {
			break
		}
		connections++
		idleTimer.Reset(idleTimeout)
		conn.Close()
	}

	if connections < 2 {
		t.Errorf("expected at least 2 connections before idle exit, got %d", connections)
	}
	idleTimer.Stop()
}

func TestLaunchdModeAgentProtocol(t *testing.T) {
	sock := launchdTestSocket(t)

	store := NewMockKeyStore()
	a := &Agent{store: store}
	key, _ := store.Generate("launchd-test", false)

	// Simulate launchd: create listener, dup fd, reconstruct listener.
	orig, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	uc := orig.(*net.UnixListener)
	uc.SetUnlinkOnClose(false)

	rawConn, err := uc.SyscallConn()
	if err != nil {
		orig.Close()
		t.Fatal(err)
	}

	var fd int
	rawConn.Control(func(f uintptr) { fd = int(f) })

	dupFd, err := dupFD(fd)
	if err != nil {
		orig.Close()
		t.Fatal(err)
	}
	orig.Close()

	f := os.NewFile(uintptr(dupFd), "test-socket")
	defer f.Close()
	l, err := net.FileListener(f)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go a.serveConn(conn)
		}
	}()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client := agent.NewClient(conn)

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	sshPub, _ := ssh.NewPublicKey(key.publicKey)
	data := sha256.Sum256([]byte("launchd test data"))
	sig, err := client.Sign(sshPub, data[:])
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil {
		t.Fatal("signature is nil")
	}
}

func TestLaunchdModeConcurrentClients(t *testing.T) {
	sock := launchdTestSocket(t)

	store := NewMockKeyStore()
	a := &Agent{store: store}
	store.Generate("concurrent-test", false)

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go a.serveConn(conn)
		}
	}()

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("unix", sock)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			c := agent.NewClient(conn)
			keys, err := c.List()
			if err != nil {
				errs <- err
				return
			}
			if len(keys) != 1 {
				errs <- fmt.Errorf("expected 1 key, got %d", len(keys))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent client: %v", err)
	}
}

// dupFD duplicates a file descriptor using dup(2).
func dupFD(fd int) (int, error) {
	newFd, err := dupSyscall(fd)
	if err != nil {
		return -1, fmt.Errorf("dup(%d): %w", fd, err)
	}
	return newFd, nil
}
