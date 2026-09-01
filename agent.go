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

	// biometricMu serializes every operation that raises a Touch ID prompt.
	// Touch ID is a single hardware resource: two concurrent
	// LocalAuthentication evaluations cancel each other, and the older one
	// fails with LAError -4 ("Canceled by another authentication") even
	// though the user did touch the sensor. keyMu alone does not prevent
	// this, because two different keys take two different locks.
	biometricMu sync.Mutex

	// Consecutive prompt-raising signatures that never completed. See
	// noteBiometricOutcome.
	stallMu    sync.Mutex
	stallCount int
	stallStart time.Time

	audit    *AuditLogger
	policy   *PeerPolicy
	notifyFn func(string)
}

func (a *Agent) notify(message string) {
	if a.notifyFn != nil {
		a.notifyFn(message)
		return
	}
	defaultNotify(message)
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

	if err := a.policy.CheckCaller(peer); err != nil {
		wrapped := fmt.Errorf("rejected signing with key %s: %w", matched.Label, err)
		a.audit.Sign(matched.Label, false, wrapped, peer)
		return nil, wrapped
	}

	// Per-key caller binding: when a key restricts its callers, the peer must
	// also satisfy one of the key's own rules (in addition to the global
	// policy above).
	if len(matched.CallerRules) > 0 && !matchesAnyRule(matched.CallerRules, peer) {
		wrapped := fmt.Errorf("rejected signing with key %s: caller not permitted for this key: %s (pid %d, signing_id=%q team_id=%q)",
			matched.Label, peer.Path, peer.PID, peer.SigningID, peer.TeamID)
		a.audit.Sign(matched.Label, false, wrapped, peer)
		return nil, wrapped
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
		a.notify(fmt.Sprintf("Waiting for Touch ID — key %q", matched.Label))
	}()

	signer, err := ssh.NewSignerFromKey(matched)
	if err != nil {
		wrapped := fmt.Errorf("failed to create signer for key %s: %w", matched.Label, err)
		a.audit.Sign(matched.Label, false, wrapped, peer)
		return nil, wrapped
	}

	// Serialize the biometric prompt itself. Keys that do not require touch
	// never raise a prompt, so they must not queue behind one: taking this
	// lock unconditionally would make -no-touch signing block on an
	// unrelated Touch ID dialog.
	if matched.RequireTouch {
		a.biometricMu.Lock()
		defer a.biometricMu.Unlock()
	}

	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		if matched.RequireTouch {
			a.noteBiometricOutcome(false, err)
		}
		wrapped := fmt.Errorf("sign with key %s: %w", matched.Label, classifySignError(err))
		a.audit.Sign(matched.Label, false, wrapped, peer)
		return nil, wrapped
	}
	if matched.RequireTouch {
		a.noteBiometricOutcome(true, nil)
	}
	debugf("Sign: success for key %s", matched.Label)
	a.audit.Sign(matched.Label, true, nil, peer)

	peerDesc := fmt.Sprintf("pid %d", peer.PID)
	if peer.Path != "" {
		peerDesc = filepath.Base(peer.Path)
	}
	go a.notify(fmt.Sprintf("Signed with key %q — %s", matched.Label, peerDesc))

	return sig, nil
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var ErrOperationUnsupported = errors.New("operation unsupported")

func (a *Agent) Add(key agent.AddedKey) error   { return ErrOperationUnsupported }
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

func defaultNotify(message string) {
	message = escapeForAppleScript(message)
	script := fmt.Sprintf(`display notification "%s" with title "touchid-agent"`, message)
	exec.Command("osascript", "-e", script).Run()
}

// Consecutive non-completions before the agent flags a possible subsystem
// stall. Three is short enough to be useful mid-incident and long enough that
// a user cancelling a couple of prompts by hand does not trip it.
const (
	biometricStallThreshold = 3
	biometricStallWindow    = 3 * time.Minute
)

// isBiometricNonCompletion reports whether err means a Touch ID prompt was
// raised but never resolved into a match: the user cancelled, the system
// cancelled it, or the client invalidated it.
//
// Note this cannot distinguish a genuine user cancellation from a wedged
// biometric subsystem — macOS reports both as LAError -2. That ambiguity is
// why noteBiometricOutcome only ever advises.
func isBiometricNonCompletion(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if !strings.Contains(msg, "com.apple.LocalAuthentication") {
		return false
	}
	for _, code := range []string{"Code=-2", "Code=-4", "Code=-9"} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

// noteBiometricOutcome tracks whether prompt-raising signatures are actually
// completing. A short run of prompts that were shown and then died without a
// match is the only signal available to the agent that the biometric
// subsystem may have stopped delivering match results — the state where
// biometrickitd logs MATCH but coreauthd never receives it.
//
// This is advisory only. It logs and notifies; it never refuses to sign.
// LocalAuthentication reports the subsystem as healthy in exactly this state
// (canEvaluatePolicy returns true, lockout state reads clean), so there is no
// pre-flight check that could do better, and failing closed on a heuristic
// would cost valid signatures.
func (a *Agent) noteBiometricOutcome(completed bool, err error) {
	a.stallMu.Lock()
	defer a.stallMu.Unlock()

	if completed {
		a.stallCount = 0
		return
	}
	if !isBiometricNonCompletion(err) {
		return
	}

	now := time.Now()
	if a.stallCount == 0 || now.Sub(a.stallStart) > biometricStallWindow {
		a.stallCount = 1
		a.stallStart = now
		return
	}
	a.stallCount++
	if a.stallCount != biometricStallThreshold {
		return
	}

	log.Printf("WARNING: %d Touch ID prompts in a row were shown but never completed. "+
		"If you are touching the sensor and nothing happens, the biometric subsystem may "+
		"have stopped delivering match results. Recover with: "+
		"sudo launchctl kickstart -k system/com.apple.biometrickitd", a.stallCount)
	go a.notify("Touch ID prompts are not completing — the biometric subsystem may be stuck. See the agent log for how to recover.")
}
