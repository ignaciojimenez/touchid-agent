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
	mu                sync.Mutex
	touchNotification *time.Timer
}

var _ agent.ExtendedAgent = &Agent{}

func (a *Agent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	keys, err := ListSEKeys()
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
	return agentKeys, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	keys, err := ListSEKeys()
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

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.touchNotification = time.NewTimer(3 * time.Second)
	go func() {
		select {
		case <-a.touchNotification.C:
		case <-ctx.Done():
			a.touchNotification.Stop()
			return
		}
		showNotification("Waiting for Touch ID authentication...")
	}()

	keys, err := ListSEKeys()
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

		signer, err := ssh.NewSignerFromKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer for key %s: %w", k.Label, err)
		}

		return signer.Sign(rand.Reader, data)
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
