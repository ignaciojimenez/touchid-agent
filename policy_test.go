//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// applePeer is a stand-in for a genuine Apple platform binary (e.g. /usr/bin/ssh).
func applePeer(signingID string) Peer {
	return Peer{PID: 10, UID: 501, Path: "/usr/bin/" + signingID, SigningID: signingID, Signed: true, ApplePlatform: true, AppleAnchored: true}
}

func TestPeerPolicy_NilSafe(t *testing.T) {
	var p *PeerPolicy
	if err := p.CheckCaller(applePeer("com.apple.ssh")); err != nil {
		t.Errorf("nil policy CheckCaller should return nil, got %v", err)
	}
	if err := p.CheckRate("key"); err != nil {
		t.Errorf("nil policy CheckRate should return nil, got %v", err)
	}
	if p.IsAllowedCaller(applePeer("com.apple.ssh")) {
		t.Error("nil policy IsAllowedCaller should return false")
	}
}

func TestPeerPolicy_Default_AllowsApplePlatformSSH(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	for _, id := range []string{"com.apple.ssh", "com.apple.scp", "com.apple.sftp", "com.apple.ssh-keygen"} {
		if !p.IsAllowedCaller(applePeer(id)) {
			t.Errorf("Apple platform %s should be allowed by default", id)
		}
	}
}

func TestPeerPolicy_Default_RejectsNonAppleSigned(t *testing.T) {
	// A validly signed third-party SSH (e.g. Homebrew via some Team ID) is
	// not Apple-platform, so the default policy rejects it.
	p := NewPeerPolicy(true, 0, nil)
	hb := Peer{PID: 11, Path: "/opt/homebrew/bin/ssh", SigningID: "org.openssh.ssh", Signed: true, AppleAnchored: true, TeamID: "ABCDE12345"}
	if p.IsAllowedCaller(hb) {
		t.Error("non-Apple-platform signed binary should be rejected by default")
	}
}

// Security: a binary that merely *claims* an Apple Signing ID but does not
// validate against "anchor apple" must not be allowed.
func TestPeerPolicy_Default_RejectsSpoofedAppleSigningID(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	spoof := Peer{PID: 12, Path: "/tmp/evil", SigningID: "com.apple.ssh", Signed: true, ApplePlatform: false}
	if p.IsAllowedCaller(spoof) {
		t.Error("binary claiming com.apple.ssh without anchor apple must be rejected")
	}
}

func TestPeerPolicy_TeamIDRule(t *testing.T) {
	p := NewPeerPolicy(true, 0, []CallerRule{{ruleTeamID, "ABCDE12345"}})
	ok := Peer{PID: 13, Path: "/Applications/Tool.app/ssh", TeamID: "ABCDE12345", Signed: true, AppleAnchored: true}
	if !p.IsAllowedCaller(ok) {
		t.Error("Apple-anchored caller with matching Team ID should be allowed")
	}
	// Security: a forged/self-signed binary claiming the Team ID is not
	// Apple-anchored, so the rule must not honor it.
	forged := Peer{PID: 14, Path: "/tmp/evil", TeamID: "ABCDE12345", Signed: true, AppleAnchored: false}
	if p.IsAllowedCaller(forged) {
		t.Error("non-Apple-anchored binary claiming Team ID must be rejected")
	}
}

func TestPeerPolicy_SigningIDRule(t *testing.T) {
	p := NewPeerPolicy(true, 0, []CallerRule{{ruleSigningID, "org.example.ssh"}})
	ok := Peer{PID: 15, Path: "/opt/x/ssh", SigningID: "org.example.ssh", Signed: true, AppleAnchored: true}
	if !p.IsAllowedCaller(ok) {
		t.Error("Apple-anchored caller with matching Signing ID should be allowed")
	}
	if p.IsAllowedCaller(Peer{SigningID: "org.example.ssh", AppleAnchored: false}) {
		t.Error("non-anchored Signing ID claim must be rejected")
	}
}

func TestPeerPolicy_CDHashRule(t *testing.T) {
	p := NewPeerPolicy(true, 0, []CallerRule{{ruleCDHash, "9F86D081"}})
	// CDHash is cryptographic, honored regardless of anchor, case-insensitive.
	if !p.IsAllowedCaller(Peer{PID: 16, Path: "/tmp/x", CDHash: "9f86d081"}) {
		t.Error("matching cdhash should be allowed regardless of anchor")
	}
	if p.IsAllowedCaller(Peer{CDHash: "deadbeef"}) {
		t.Error("non-matching cdhash should be rejected")
	}
}

func TestPeerPolicy_PathRule_EscapeHatch(t *testing.T) {
	// Path rules authorize even unsigned callers (the escape hatch).
	p := NewPeerPolicy(true, 0, []CallerRule{{rulePath, "/opt/homebrew/bin/ssh"}})
	if !p.IsAllowedCaller(Peer{PID: 17, Path: "/opt/homebrew/bin/ssh", Signed: false}) {
		t.Error("path rule should allow the configured path even when unsigned")
	}
	if p.IsAllowedCaller(Peer{Path: "/opt/homebrew/bin/scp"}) {
		t.Error("path rule should not allow a different path")
	}
}

func TestPeerPolicy_PathRule_SymlinkResolved(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "ssh")
	os.WriteFile(real, []byte("#!/bin/sh\n"), 0755)
	link := filepath.Join(dir, "ssh-link")
	os.Symlink(real, link)
	realResolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPeerPolicy(true, 0, []CallerRule{{rulePath, link}})
	if !p.IsAllowedCaller(Peer{Path: realResolved}) {
		t.Error("path rule should match via resolved symlink")
	}
}

func TestPeerPolicy_PathRules(t *testing.T) {
	p := NewPeerPolicy(true, 0, []CallerRule{
		{ruleTeamID, "ABCDE12345"},
		{rulePath, "/opt/homebrew/bin/ssh"},
		{rulePath, "/usr/local/bin/ssh"},
	})
	if got := p.pathRules(); len(got) != 2 {
		t.Errorf("pathRules() = %v, want 2 path rules", got)
	}
}

func TestPeerPolicy_CheckCaller_EnforceOff(t *testing.T) {
	p := NewPeerPolicy(false, 0, nil)
	if err := p.CheckCaller(Peer{PID: 1, Path: "/tmp/evil-ssh"}); err != nil {
		t.Errorf("enforce=false should allow all callers, got %v", err)
	}
}

func TestPeerPolicy_CheckCaller_RejectsUnknown(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	if err := p.CheckCaller(Peer{PID: 1, Path: "/tmp/evil-ssh"}); err == nil {
		t.Error("enforce=true should reject unknown callers")
	}
}

func TestPeerPolicy_CheckCaller_RejectsEmptyPeer(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	if err := p.CheckCaller(Peer{PID: 1}); err == nil {
		t.Error("enforce=true should reject an unidentifiable peer")
	}
}

func TestPeerPolicy_CheckCaller_AllowsApple(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	if err := p.CheckCaller(applePeer("com.apple.ssh")); err != nil {
		t.Errorf("should allow Apple platform ssh, got %v", err)
	}
}

func TestPeerPolicy_RequireHardened(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	p.requireHardened = true

	hardened := applePeer("com.apple.ssh")
	hardened.Hardened = true
	if err := p.CheckCaller(hardened); err != nil {
		t.Errorf("hardened Apple caller should be allowed, got %v", err)
	}

	// Matches a rule but is not hardened -> rejected by the extra gate.
	notHardened := applePeer("com.apple.ssh") // Hardened defaults to false
	if err := p.CheckCaller(notHardened); err == nil {
		t.Error("non-hardened caller should be rejected when require-hardened is set")
	}
}

func TestParseCallerRule(t *testing.T) {
	cases := []struct {
		line string
		want CallerRule
	}{
		{"team-id:ABCDE12345", CallerRule{ruleTeamID, "ABCDE12345"}},
		{"teamid:ABCDE12345", CallerRule{ruleTeamID, "ABCDE12345"}},
		{"signing-id:org.example.ssh", CallerRule{ruleSigningID, "org.example.ssh"}},
		{"cdhash:9f86d081", CallerRule{ruleCDHash, "9f86d081"}},
		{"path:/opt/homebrew/bin/ssh", CallerRule{rulePath, "/opt/homebrew/bin/ssh"}},
		{"/usr/local/bin/ssh", CallerRule{rulePath, "/usr/local/bin/ssh"}}, // bare path back-compat
	}
	for _, c := range cases {
		got, err := parseCallerRule(c.line)
		if err != nil {
			t.Errorf("parseCallerRule(%q) error: %v", c.line, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseCallerRule(%q) = %+v, want %+v", c.line, got, c.want)
		}
	}
}

func TestParseCallerRule_Errors(t *testing.T) {
	for _, line := range []string{"bogus", "relative/path", "team-id:", "unknown:value"} {
		if _, err := parseCallerRule(line); err == nil {
			t.Errorf("parseCallerRule(%q) should error", line)
		}
	}
}

func TestLoadAllowedCallers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "callers.txt")
	content := "# Comment\nteam-id:ABCDE12345\n\n/usr/local/bin/ssh\npath:/opt/homebrew/bin/ssh\ncdhash:deadbeef\n"
	os.WriteFile(path, []byte(content), 0644)

	rules, err := loadAllowedCallers(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []CallerRule{
		{ruleTeamID, "ABCDE12345"},
		{rulePath, "/usr/local/bin/ssh"},
		{rulePath, "/opt/homebrew/bin/ssh"},
		{ruleCDHash, "deadbeef"},
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(rules), len(want), rules)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, rules[i], want[i])
		}
	}
}

func TestLoadAllowedCallers_MissingFile(t *testing.T) {
	_, err := loadAllowedCallers("/nonexistent/file")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadAllowedCallers_BadLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "callers.txt")
	os.WriteFile(path, []byte("team-id:ABCDE12345\nnot-a-valid-rule\n"), 0644)
	if _, err := loadAllowedCallers(path); err == nil {
		t.Error("expected error for an invalid rule line")
	}
}

func TestPeerPolicy_CheckRate_Disabled(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	for i := 0; i < 200; i++ {
		if err := p.CheckRate("key"); err != nil {
			t.Fatalf("rate limit disabled but got error at iteration %d: %v", i, err)
		}
	}
}

func TestPeerPolicy_CheckRate_Enforced(t *testing.T) {
	p := NewPeerPolicy(true, 5, nil)
	for i := 0; i < 5; i++ {
		if err := p.CheckRate("key"); err != nil {
			t.Fatalf("should allow first 5, failed at %d: %v", i, err)
		}
	}
	if err := p.CheckRate("key"); err == nil {
		t.Error("should reject after exceeding rate limit")
	}
}

func TestPeerPolicy_CheckRate_PerKey(t *testing.T) {
	p := NewPeerPolicy(true, 2, nil)
	p.CheckRate("key-a")
	p.CheckRate("key-a")
	if err := p.CheckRate("key-a"); err == nil {
		t.Error("key-a should be rate limited")
	}
	if err := p.CheckRate("key-b"); err != nil {
		t.Errorf("key-b should not be rate limited, got %v", err)
	}
}

func TestPeerPolicy_CheckRate_Ceiling(t *testing.T) {
	p := NewPeerPolicy(true, 9999, nil)
	if p.rateLimit != rateLimitCeiling {
		t.Errorf("rate limit should be capped at %d, got %d", rateLimitCeiling, p.rateLimit)
	}
}

func TestPeerPolicy_CheckRate_Concurrent(t *testing.T) {
	p := NewPeerPolicy(true, 50, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allowed, rejected int
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := p.CheckRate("concurrent-key")
			mu.Lock()
			if err == nil {
				allowed++
			} else {
				rejected++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if allowed != 50 {
		t.Errorf("expected 50 allowed, got %d (rejected %d)", allowed, rejected)
	}
}

func TestRateBucket_SlidingWindow(t *testing.T) {
	b := &rateBucket{}
	for i := 0; i < 3; i++ {
		if !b.allow(3) {
			t.Fatalf("should allow request %d", i)
		}
	}
	if b.allow(3) {
		t.Error("should reject after limit")
	}
}
