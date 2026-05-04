//go:build darwin

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Agent struct {
	storeMu sync.RWMutex
	store   KeyStore
	keyMu   sync.Map // label -> *sync.Mutex
}

func (a *Agent) keyLock(label string) *sync.Mutex {
	v, _ := a.keyMu.LoadOrStore(label, &sync.Mutex{})
	return v.(*sync.Mutex)
}

var _ agent.ExtendedAgent = &Agent{}

const connIdleTimeout = 10 * time.Minute

// idleConn resets the deadline on every read, converting the timeout
// from an absolute wall-clock cutoff into a true idle timer.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

func (a *Agent) serveConn(c net.Conn) {
	debugf("new client connection from %s", c.RemoteAddr())
	ic := &idleConn{Conn: c, timeout: connIdleTimeout}
	if err := agent.ServeAgent(a, ic); err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
	debugf("client disconnected")
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.storeMu.RLock()
	defer a.storeMu.RUnlock()

	keys, err := a.store.List()
	if err != nil {
		return nil, fmt.Errorf("could not list keys: %w", err)
	}

	var agentKeys []*agent.Key
	for _, k := range keys {
		pk, err := ssh.NewPublicKey(k.publicKey)
		if err != nil {
			log.Printf("skipping key %s: %v", k.Label, err)
			continue
		}
		agentKeys = append(agentKeys, &agent.Key{
			Format:  pk.Type(),
			Blob:    pk.Marshal(),
			Comment: fmt.Sprintf("touchid-agent: %s", k.Label),
		})
	}
	debugf("List: returning %d key(s)", len(agentKeys))
	return agentKeys, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.storeMu.RLock()
	defer a.storeMu.RUnlock()

	keys, err := a.store.List()
	if err != nil {
		return nil, fmt.Errorf("could not list keys: %w", err)
	}

	var signers []ssh.Signer
	for _, k := range keys {
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			log.Printf("skipping key %s: %v", k.Label, err)
			continue
		}
		signers = append(signers, s)
	}
	return signers, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignatureFlags control RSA algorithm negotiation (SHA-256/512) and are
// irrelevant for ECDSA P-256 which always uses SHA-256. Safe to ignore.
func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	// Phase 1: find the matching key under a short read lock.
	a.storeMu.RLock()
	keys, err := a.store.List()
	a.storeMu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("could not list keys: %w", err)
	}

	var matched *SEKey
	for _, k := range keys {
		pk, err := ssh.NewPublicKey(k.publicKey)
		if err != nil {
			continue
		}
		if bytes.Equal(pk.Marshal(), key.Marshal()) {
			matched = k
			break
		}
	}
	if matched == nil {
		return nil, errors.New("no matching key found")
	}

	// Phase 2: acquire only this key's lock for the signing operation.
	// Independent keys can sign concurrently (parallel Touch ID prompts).
	mu := a.keyLock(matched.Label)
	mu.Lock()
	defer mu.Unlock()

	debugf("Sign: matched key %s (touch=%v)", matched.Label, matched.RequireTouch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.NewTimer(3 * time.Second)
	go func() {
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
		showNotification("Waiting for Touch ID authentication...")
	}()

	signer, err := ssh.NewSignerFromKey(matched)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer for key %s: %w", matched.Label, err)
	}

	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, fmt.Errorf("sign with key %s: %w", matched.Label, classifySignError(err))
	}
	debugf("Sign: success for key %s", matched.Label)
	return sig, nil
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var ErrOperationUnsupported = errors.New("operation unsupported")

func (a *Agent) Add(key agent.AddedKey) error  { return ErrOperationUnsupported }
func (a *Agent) Remove(key ssh.PublicKey) error { return ErrOperationUnsupported }
func (a *Agent) RemoveAll() error               { return ErrOperationUnsupported }
func (a *Agent) Lock(passphrase []byte) error   { return ErrOperationUnsupported }
func (a *Agent) Unlock(passphrase []byte) error { return ErrOperationUnsupported }
