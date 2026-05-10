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

func testSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tid-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return fmt.Sprintf("%s/a.sock", dir)
}

func startTestAgent(t *testing.T) (agent.ExtendedAgent, string, func()) {
	t.Helper()

	sock := testSocketPath(t)

	store := NewMockKeyStore()
	a := &Agent{store: store}
	store.Generate("integration-test", false)

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

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
		l.Close()
		t.Fatal(err)
	}

	client := agent.NewClient(conn)
	cleanup := func() {
		conn.Close()
		l.Close()
		os.Remove(sock)
	}
	return client, sock, cleanup
}

func TestAgentSocket_ListKeys(t *testing.T) {
	client, _, cleanup := startTestAgent(t)
	defer cleanup()

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Format != "ecdsa-sha2-nistp256" {
		t.Errorf("format = %q, want ecdsa-sha2-nistp256", keys[0].Format)
	}
}

func TestAgentSocket_SignData(t *testing.T) {
	client, _, cleanup := startTestAgent(t)
	defer cleanup()

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("no keys")
	}

	pubKey, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		t.Fatal(err)
	}

	data := sha256.Sum256([]byte("test data for signing"))
	sig, err := client.Sign(pubKey, data[:])
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil {
		t.Fatal("signature is nil")
	}
}

func TestAgentSocket_MultipleClients(t *testing.T) {
	sock := testSocketPath(t)

	store := NewMockKeyStore()
	a := &Agent{store: store}
	store.Generate("multi-client", false)

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
	errs := make(chan error, 5)
	for i := 0; i < 5; i++ {
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
		if err != nil {
			t.Errorf("concurrent client error: %v", err)
		}
	}
}

func TestAgentSocket_ClientDisconnect(t *testing.T) {
	sock := testSocketPath(t)

	store := NewMockKeyStore()
	a := &Agent{store: store}

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

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	conn2, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal("agent should accept new connections after disconnect")
	}
	defer conn2.Close()

	c := agent.NewClient(conn2)
	_, err = c.List()
	if err != nil {
		t.Fatal(err)
	}
}

func TestAgentSocket_Permissions(t *testing.T) {
	sock := testSocketPath(t)

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := os.Chmod(sock, 0600); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("socket permissions = %o, want 0600", perm)
	}
}

func TestAgentSocket_GracefulShutdown(t *testing.T) {
	sock := testSocketPath(t)

	store := NewMockKeyStore()
	a := &Agent{
		store:  store,
		audit:  NewStderrAuditLogger(),
		policy: NewPeerPolicy(false, 0, nil),
	}
	store.Generate("drain-test", false)

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the graceful shutdown accept loop from cmdRun.
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				a.serveConn(conn)
			}()
		}
	}()

	// Open a client connection and keep it alive.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	client := agent.NewClient(conn)

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// Close the listener (simulates SIGTERM closing it).
	l.Close()

	// The existing connection should still be usable.
	keys, err = client.List()
	if err != nil {
		t.Fatalf("existing connection should survive listener close: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after listener close, got %d", len(keys))
	}

	// Close the client; the wg.Wait() should then complete.
	conn.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for connections to drain")
	}
}
