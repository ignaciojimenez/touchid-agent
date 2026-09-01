//go:build darwin

package main

import (
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// instrumentSign replaces a key's signing function with one that records how
// many are in flight at once, standing in for the window during which a Touch
// ID prompt is on screen.
func instrumentSign(k *Key, inFlight, maxSeen *int32, dwell time.Duration) {
	k.signFn = func(_ string, _ []byte) ([]byte, error) {
		n := atomic.AddInt32(inFlight, 1)
		for {
			m := atomic.LoadInt32(maxSeen)
			if n <= m || atomic.CompareAndSwapInt32(maxSeen, m, n) {
				break
			}
		}
		time.Sleep(dwell)
		atomic.AddInt32(inFlight, -1)
		return []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, nil
	}
}

func testAgent(store KeyStore) *Agent {
	return &Agent{
		store:    store,
		audit:    NewStderrAuditLogger(),
		policy:   NewPeerPolicy(false, 0, nil),
		notifyFn: func(string) {},
	}
}

func signConcurrently(t *testing.T, a *Agent, keys []*Key, perKey int) {
	t.Helper()
	digest := sha256.Sum256([]byte("concurrency probe"))
	var wg sync.WaitGroup
	for _, k := range keys {
		pub, err := ssh.NewPublicKey(k.publicKey)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < perKey; i++ {
			wg.Add(1)
			go func(pk ssh.PublicKey) {
				defer wg.Done()
				a.signFor(pk, digest[:], Peer{})
			}(pub)
		}
	}
	wg.Wait()
}

// Two touch-required keys must not raise Touch ID prompts at the same time.
// Concurrent LocalAuthentication evaluations cancel each other and the older
// one fails with LAError -4 even though the user did touch the sensor.
func TestTouchRequiredSignsNeverOverlap(t *testing.T) {
	store := NewMockKeyStore()
	var inFlight, maxSeen int32
	var keys []*Key
	for _, label := range []string{"ssh", "sign"} {
		k, err := store.Generate(label, true)
		if err != nil {
			t.Fatal(err)
		}
		instrumentSign(k, &inFlight, &maxSeen, 120*time.Millisecond)
		keys = append(keys, k)
	}

	signConcurrently(t, testAgent(store), keys, 3)

	if maxSeen > 1 {
		t.Errorf("%d concurrent Touch ID operations; prompts must be serialized", maxSeen)
	}
}

// Keys created with -no-touch raise no prompt, so they must not queue behind
// one. Serializing them would turn an instant signature into a wait for an
// unrelated Touch ID dialog.
func TestNoTouchSignsAreNotBlockedByTouchPrompt(t *testing.T) {
	store := NewMockKeyStore()

	touchKey, err := store.Generate("ssh", true)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	touchKey.signFn = func(_ string, _ []byte) ([]byte, error) {
		once.Do(func() { close(entered) })
		<-release
		return []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, nil
	}

	fastKey, err := store.Generate("deploy", false)
	if err != nil {
		t.Fatal(err)
	}

	a := testAgent(store)
	digest := sha256.Sum256([]byte("no-touch probe"))
	touchPub, _ := ssh.NewPublicKey(touchKey.publicKey)
	fastPub, _ := ssh.NewPublicKey(fastKey.publicKey)

	go a.signFor(touchPub, digest[:], Peer{}) // holds the biometric lock
	<-entered
	defer close(release)

	done := make(chan error, 1)
	go func() {
		_, err := a.signFor(fastPub, digest[:], Peer{})
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("no-touch signature failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no-touch signature blocked behind a Touch ID prompt")
	}
}

// A run of prompts that were shown and then died without a match is the only
// signal the agent has that the biometric subsystem may have stopped
// delivering match results. It must advise, never refuse.
func TestBiometricStallIsReportedAfterThreshold(t *testing.T) {
	notices := make(chan string, 8)
	a := testAgent(NewMockKeyStore())
	a.notifyFn = func(m string) { notices <- m }

	cancelled := errors.New(`Error Domain=com.apple.LocalAuthentication Code=-2 "Canceled by user." UserInfo={}`)
	for i := 0; i < biometricStallThreshold; i++ {
		a.noteBiometricOutcome(false, cancelled)
	}

	select {
	case m := <-notices:
		if !strings.Contains(strings.ToLower(m), "touch id") {
			t.Errorf("unexpected stall notice: %q", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no stall notice after %d non-completions", biometricStallThreshold)
	}
}

func TestBiometricStallResetsOnSuccess(t *testing.T) {
	notices := make(chan string, 8)
	a := testAgent(NewMockKeyStore())
	a.notifyFn = func(m string) { notices <- m }

	cancelled := errors.New(`Error Domain=com.apple.LocalAuthentication Code=-2 "Canceled by user." UserInfo={}`)
	for i := 0; i < biometricStallThreshold*3; i++ {
		a.noteBiometricOutcome(false, cancelled)
		a.noteBiometricOutcome(true, nil)
	}

	select {
	case m := <-notices:
		t.Errorf("stall reported despite signatures succeeding in between: %q", m)
	case <-time.After(200 * time.Millisecond):
	}
}

// Errors that are not biometric non-completions must not count towards a
// stall, or an unrelated fault would masquerade as a wedged sensor.
func TestBiometricStallIgnoresUnrelatedErrors(t *testing.T) {
	notices := make(chan string, 8)
	a := testAgent(NewMockKeyStore())
	a.notifyFn = func(m string) { notices <- m }

	unrelated := errors.New(`Error Domain=NSOSStatusErrorDomain Code=-25308 "unable to sign digest"`)
	for i := 0; i < biometricStallThreshold*2; i++ {
		a.noteBiometricOutcome(false, unrelated)
	}

	select {
	case m := <-notices:
		t.Errorf("non-biometric error counted as a stall: %q", m)
	case <-time.After(200 * time.Millisecond):
	}
}

// Every one of these was copied from a real failure in the audit log. Before
// this change all of them fell through to the default branch, so the agent
// never once produced an actionable message in production.
func TestClassifySignErrorHandlesRealCryptoKitErrors(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"display asleep / lid closed",
			`Error Domain=NSOSStatusErrorDomain Code=-25308 "<sepk:p256(u) kid=b46afd2923f5a668>: unable to sign digest" UserInfo={AKSError=-536870174}`,
			"unavailable",
		},
		{
			"user cancel",
			`Error Domain=com.apple.LocalAuthentication Code=-2 "Canceled by user." UserInfo={BiometryType=1}`,
			"cancelled",
		},
		{
			"preempted by a concurrent evaluation",
			`Error Domain=com.apple.LocalAuthentication Code=-4 "Canceled by another authentication." UserInfo={Subcode=34}`,
			"another authentication",
		},
		{
			"system authentication in progress",
			`Error Domain=com.apple.LocalAuthentication Code=-4 "System authentication is running." UserInfo={BiometryType=1}`,
			"system authentication",
		},
		{
			"invalidated by client",
			`Error Domain=com.apple.LocalAuthentication Code=-9 "Invalidated by client." UserInfo={}`,
			"invalidated",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifySignError(errors.New(tc.in)).Error()
			if !strings.Contains(strings.ToLower(got), tc.want) {
				t.Errorf("classifySignError(%s)\n  got:  %q\n  want substring: %q", tc.name, got, tc.want)
			}
			if strings.HasPrefix(got, "sign: ") {
				t.Errorf("%s fell through to the default branch: %q", tc.name, got)
			}
		})
	}
}
