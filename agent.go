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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Agent struct {
	storeMu sync.RWMutex
	store   KeyStore
	keyMu   sync.Map // label -> *sync.Mutex
	audit   *AuditLogger
	policy  *PeerPolicy
}

func (a *Agent) keyLock(label string) *sync.Mutex {
	v, _ := a.keyMu.LoadOrStore(label, &sync.Mutex{})
	return v.(*sync.Mutex)
}

var _ agent.ExtendedAgent = &Agent{}

const connIdleTimeout = 10 * time.Minute

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

// connAgent attaches per-connection peer credentials so signing
// operations can attribute audit events to the calling process. All
// non-signing methods delegate to the embedded *Agent.
type connAgent struct {
	*Agent
	peer Peer
}

func (a *Agent) serveConn(c net.Conn) {
	debugf("new client connection from %s", c.RemoteAddr())
	peer := peerCreds(c)
	debugf("peer creds: pid=%d uid=%d", peer.PID, peer.UID)
	ca := &connAgent{Agent: a, peer: peer}
	ic := &idleConn{Conn: c, timeout: connIdleTimeout}
	if err := agent.ServeAgent(ca, ic); err != io.EOF {
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
	return a.signFor(key, data, Peer{})
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return a.signFor(key, data, Peer{})
}

func (c *connAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.signFor(key, data, c.peer)
}

func (c *connAgent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return c.signFor(key, data, c.peer)
}

func (a *Agent) signFor(key ssh.PublicKey, data []byte, peer Peer) (*ssh.Signature, error) {
	a.storeMu.RLock()
	keys, err := a.store.List()
	a.storeMu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("could not list keys: %w", err)
	}

	var matched *Key
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

	mu := a.keyLock(matched.Label)
	mu.Lock()
	defer mu.Unlock()

	debugf("Sign: matched key %s (touch=%v, peer=%s pid=%d)", matched.Label, matched.RequireTouch, peer.Path, peer.PID)

	if !matched.RequireTouch {
		if err := a.policy.CheckCaller(peer); err != nil {
			wrapped := fmt.Errorf("rejected signing with key %s: %w", matched.Label, err)
			a.audit.Sign(matched.Label, false, wrapped, peer)
			return nil, wrapped
		}
	}

	if err := a.policy.CheckRate(matched.Label); err != nil {
		wrapped := fmt.Errorf("rejected signing with key %s: %w", matched.Label, err)
		a.audit.Sign(matched.Label, false, wrapped, peer)
		return nil, wrapped
	}

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
		showNotification(fmt.Sprintf("Waiting for Touch ID — key %q", matched.Label))
	}()

	signer, err := ssh.NewSignerFromKey(matched)
	if err != nil {
		wrapped := fmt.Errorf("failed to create signer for key %s: %w", matched.Label, err)
		a.audit.Sign(matched.Label, false, wrapped, peer)
		return nil, wrapped
	}

	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		wrapped := fmt.Errorf("sign with key %s: %w", matched.Label, classifySignError(err))
		a.audit.Sign(matched.Label, false, wrapped, peer)
		return nil, wrapped
	}
	debugf("Sign: success for key %s", matched.Label)
	a.audit.Sign(matched.Label, true, nil, peer)

	if !matched.RequireTouch {
		peerDesc := fmt.Sprintf("pid %d", peer.PID)
		if peer.Path != "" {
			peerDesc = filepath.Base(peer.Path)
		}
		go showNotification(fmt.Sprintf("Signed with key %q — %s", matched.Label, peerDesc))
	}

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

func escapeForAppleScript(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "$(", "")
	return s
}

func showNotification(message string) {
	message = escapeForAppleScript(message)
	script := fmt.Sprintf(`display notification "%s" with title "touchid-agent"`, message)
	exec.Command("osascript", "-e", script).Run()
}
