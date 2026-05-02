//go:build darwin

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func newTestAgent(t *testing.T) (*Agent, *MockKeyStore) {
	t.Helper()
	store := NewMockKeyStore()
	a := &Agent{store: store}
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
	store.Generate("test", true, false)

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
	store.Generate("ssh", true, false)
	store.Generate("git", false, false)

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
	store.Generate("test", true, false)

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
	key, _ := store.Generate("test", false, false)

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
	key, _ := store.Generate("test", false, false)

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
	store.Generate("key1", true, false)
	store.Generate("key2", false, false)

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
	key, _ := store.Generate("test", false, false)
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
