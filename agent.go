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
	mu    sync.Mutex
	store KeyStore
}

var _ agent.ExtendedAgent = &Agent{}

const connIdleTimeout = 10 * time.Minute

func (a *Agent) serveConn(c net.Conn) {
	debugf("new client connection from %s", c.RemoteAddr())
	c.SetDeadline(time.Now().Add(connIdleTimeout))
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
	debugf("client disconnected")
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

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
	a.mu.Lock()
	defer a.mu.Unlock()

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
	a.mu.Lock()
	defer a.mu.Unlock()

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

	keys, err := a.store.List()
	if err != nil {
		return nil, fmt.Errorf("could not list keys: %w", err)
	}

	for _, k := range keys {
		pk, err := ssh.NewPublicKey(k.publicKey)
		if err != nil {
			continue
		}
		if !bytes.Equal(pk.Marshal(), key.Marshal()) {
			continue
		}

		debugf("Sign: matched key %s (touch=%v)", k.Label, k.RequireTouch)
		signer, err := ssh.NewSignerFromKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer for key %s: %w", k.Label, err)
		}

		sig, err := signer.Sign(rand.Reader, data)
		if err != nil {
			return nil, fmt.Errorf("sign with key %s: %w", k.Label, err)
		}
		debugf("Sign: success for key %s", k.Label)
		return sig, nil
	}

	return nil, errors.New("no matching key found")
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
