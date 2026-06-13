//go:build darwin

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func newTestAgent(t *testing.T) (*Agent, *MockKeyStore) {
	t.Helper()
	store := NewMockKeyStore()
	a := &Agent{
		store:  store,
		audit:  NewStderrAuditLogger(),
		policy: NewPeerPolicy(false, 0, nil),
	}
	return a, store
}

func TestAgent_List_Empty(t *testing.T) {
	a, _ := newTestAgent(t)
	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestAgent_List_SingleKey(t *testing.T) {
	a, store := newTestAgent(t)
	store.Generate("test", true)

	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Comment != "touchid-agent: test" {
		t.Errorf("comment = %q, want %q", keys[0].Comment, "touchid-agent: test")
	}
	if keys[0].Format != "ecdsa-sha2-nistp256" {
		t.Errorf("format = %q, want %q", keys[0].Format, "ecdsa-sha2-nistp256")
	}
}

func TestAgent_List_MultipleKeys(t *testing.T) {
	a, store := newTestAgent(t)
	store.Generate("ssh", true)
	store.Generate("git", false)

	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestAgent_Signers(t *testing.T) {
	a, store := newTestAgent(t)
	store.Generate("test", true)

	signers, err := a.Signers()
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}
}

func TestAgent_Sign_MatchingKey(t *testing.T) {
	a, store := newTestAgent(t)
	key, _ := store.Generate("test", false)

	sshPub, err := ssh.NewPublicKey(key.publicKey)
	if err != nil {
		t.Fatal(err)
	}

	data := sha256.Sum256([]byte("test data"))
	sig, err := a.Sign(sshPub, data[:])
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil {
		t.Fatal("signature is nil")
	}
	if sig.Format != "ecdsa-sha2-nistp256" {
		t.Errorf("signature format = %q, want ecdsa-sha2-nistp256", sig.Format)
	}
}

func TestAgent_Sign_PeerCheckRejectsTouchRequiredKey(t *testing.T) {
	a, store := newTestAgent(t)
	a.policy = NewPeerPolicy(true, 0, nil)
	key, _ := store.Generate("touch-key", true)

	sshPub, err := ssh.NewPublicKey(key.publicKey)
	if err != nil {
		t.Fatal(err)
	}

	data := sha256.Sum256([]byte("test data"))
	_, err = a.signFor(sshPub, data[:], Peer{PID: 7, Path: "/tmp/evil-ssh"})
	if err == nil {
		t.Fatal("expected peer-check rejection for touch-required key")
	}
	if !strings.Contains(err.Error(), "not in allowlist") {
		t.Fatalf("error = %v, want allowlist rejection", err)
	}
}

func TestAgent_Sign_NoMatchingKey(t *testing.T) {
	a, _ := newTestAgent(t)

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sshPub, _ := ssh.NewPublicKey(&priv.PublicKey)

	data := sha256.Sum256([]byte("test"))
	_, err := a.Sign(sshPub, data[:])
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

func TestAgent_SignWithFlags_Zero(t *testing.T) {
	a, store := newTestAgent(t)
	key, _ := store.Generate("test", false)

	sshPub, _ := ssh.NewPublicKey(key.publicKey)
	data := sha256.Sum256([]byte("test data"))

	sig, err := a.SignWithFlags(sshPub, data[:], 0)
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil {
		t.Fatal("signature is nil")
	}
}

func TestAgent_Add_Rejected(t *testing.T) {
	a, _ := newTestAgent(t)
	err := a.Add(agent.AddedKey{})
	if err != ErrOperationUnsupported {
		t.Errorf("Add() = %v, want ErrOperationUnsupported", err)
	}
}

func TestAgent_Remove_Rejected(t *testing.T) {
	a, _ := newTestAgent(t)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sshPub, _ := ssh.NewPublicKey(&priv.PublicKey)
	err := a.Remove(sshPub)
	if err != ErrOperationUnsupported {
		t.Errorf("Remove() = %v, want ErrOperationUnsupported", err)
	}
}

func TestAgent_RemoveAll_Rejected(t *testing.T) {
	a, _ := newTestAgent(t)
	err := a.RemoveAll()
	if err != ErrOperationUnsupported {
		t.Errorf("RemoveAll() = %v, want ErrOperationUnsupported", err)
	}
}

func TestAgent_Lock_Rejected(t *testing.T) {
	a, _ := newTestAgent(t)
	err := a.Lock([]byte("pass"))
	if err != ErrOperationUnsupported {
		t.Errorf("Lock() = %v, want ErrOperationUnsupported", err)
	}
}

func TestAgent_Unlock_Rejected(t *testing.T) {
	a, _ := newTestAgent(t)
	err := a.Unlock([]byte("pass"))
	if err != ErrOperationUnsupported {
		t.Errorf("Unlock() = %v, want ErrOperationUnsupported", err)
	}
}

func TestAgent_Extension_Rejected(t *testing.T) {
	a, _ := newTestAgent(t)
	_, err := a.Extension("test", nil)
	if err != agent.ErrExtensionUnsupported {
		t.Errorf("Extension() = %v, want ErrExtensionUnsupported", err)
	}
}

func TestAgent_ConcurrentList(t *testing.T) {
	a, store := newTestAgent(t)
	store.Generate("key1", true)
	store.Generate("key2", false)

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := a.List()
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent List error: %v", err)
	}
}

func TestAgent_ConcurrentSign(t *testing.T) {
	a, store := newTestAgent(t)
	key, _ := store.Generate("test", false)
	sshPub, _ := ssh.NewPublicKey(key.publicKey)

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := sha256.Sum256([]byte("concurrent test"))
			_, err := a.Sign(sshPub, data[:])
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Sign error: %v", err)
	}
}

func TestAgent_ConcurrentSign_DifferentKeys(t *testing.T) {
	a, store := newTestAgent(t)
	key1, _ := store.Generate("key-a", false)
	key2, _ := store.Generate("key-b", false)
	pub1, _ := ssh.NewPublicKey(key1.publicKey)
	pub2, _ := ssh.NewPublicKey(key2.publicKey)

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			data := sha256.Sum256([]byte("key-a data"))
			if _, err := a.Sign(pub1, data[:]); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			data := sha256.Sum256([]byte("key-b data"))
			if _, err := a.Sign(pub2, data[:]); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent multi-key Sign error: %v", err)
	}
}

func TestAgent_Sign_NotifiesOnNoTouchKey(t *testing.T) {
	var mu sync.Mutex
	var messages []string

	a, store := newTestAgent(t)
	a.notifyFn = func(msg string) {
		mu.Lock()
		messages = append(messages, msg)
		mu.Unlock()
	}
	key, _ := store.Generate("notify-test", false)
	sshPub, _ := ssh.NewPublicKey(key.publicKey)

	data := sha256.Sum256([]byte("test"))
	_, err := a.Sign(sshPub, data[:])
	if err != nil {
		t.Fatal(err)
	}

	// The no-touch notification is sent in a goroutine; give it a moment.
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, m := range messages {
		if strings.Contains(m, "notify-test") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected notification mentioning key label, got %v", messages)
	}
}

func TestAgent_Sign_NotifiesOnTouchKey(t *testing.T) {
	a, store := newTestAgent(t)
	messages := make(chan string, 1)
	a.notifyFn = func(msg string) {
		messages <- msg
	}
	key, _ := store.Generate("touch-key", true)
	sshPub, _ := ssh.NewPublicKey(key.publicKey)

	data := sha256.Sum256([]byte("test"))
	_, err := a.Sign(sshPub, data[:])
	if err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-messages:
		if !strings.Contains(msg, "touch-key") {
			t.Fatalf("notification = %q, want key label", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("expected signing notification")
	}
}
