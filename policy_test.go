//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPeerPolicy_NilSafe(t *testing.T) {
	var p *PeerPolicy
	if err := p.CheckCaller(Peer{PID: 1, Path: "/usr/bin/ssh"}); err != nil {
		t.Errorf("nil policy CheckCaller should return nil, got %v", err)
	}
	if err := p.CheckRate("key"); err != nil {
		t.Errorf("nil policy CheckRate should return nil, got %v", err)
	}
	if p.IsAllowedCaller("/usr/bin/ssh") {
		t.Error("nil policy IsAllowedCaller should return false")
	}
}

func TestPeerPolicy_IsAllowedCaller_DefaultPath(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	if !p.IsAllowedCaller("/usr/bin/ssh") {
		t.Error("/usr/bin/ssh should be allowed by default")
	}
}

func TestPeerPolicy_IsAllowedCaller_DefaultExcludesHomebrew(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	for _, path := range []string{"/opt/homebrew/bin/ssh", "/usr/local/bin/ssh"} {
		if p.IsAllowedCaller(path) {
			t.Errorf("%s should not be allowed by default", path)
		}
	}
}

func TestPeerPolicy_IsAllowedCaller_ExplicitHomebrew(t *testing.T) {
	path := "/opt/homebrew/bin/ssh"
	p := NewPeerPolicy(true, 0, []string{path})
	if !p.IsAllowedCaller(path) {
		t.Error("explicit Homebrew caller should be allowed")
	}
}

func TestPeerPolicy_IsAllowedCaller_EmptyPath(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	if p.IsAllowedCaller("") {
		t.Error("empty path should not be allowed")
	}
}

func TestPeerPolicy_IsAllowedCaller_UnknownPath(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	if p.IsAllowedCaller("/tmp/evil-ssh") {
		t.Error("unknown path should not be allowed")
	}
}

func TestPeerPolicy_IsAllowedCaller_ExtraPaths(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "my-ssh")
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0755)

	// proc_pidpath returns resolved paths, so simulate that
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPeerPolicy(true, 0, []string{bin})
	if !p.IsAllowedCaller(resolved) {
		t.Error("extra caller path should be allowed")
	}
}

func TestPeerPolicy_IsAllowedCaller_Symlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "ssh")
	os.WriteFile(real, []byte("#!/bin/sh\n"), 0755)
	link := filepath.Join(dir, "ssh-link")
	os.Symlink(real, link)

	// proc_pidpath returns the resolved path of the running binary
	realResolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPeerPolicy(true, 0, []string{link})
	if !p.IsAllowedCaller(realResolved) {
		t.Error("should allow caller via resolved symlink")
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

func TestPeerPolicy_CheckCaller_RejectsEmptyPath(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	if err := p.CheckCaller(Peer{PID: 1}); err == nil {
		t.Error("enforce=true should reject empty path")
	}
}

func TestPeerPolicy_CheckCaller_AllowsKnown(t *testing.T) {
	p := NewPeerPolicy(true, 0, nil)
	if err := p.CheckCaller(Peer{PID: 1, Path: "/usr/bin/ssh"}); err != nil {
		t.Errorf("should allow /usr/bin/ssh, got %v", err)
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

func TestLoadAllowedCallers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "callers.txt")
	content := "# Comment\n/usr/bin/ssh\n\n/custom/path\n# Another comment\n"
	os.WriteFile(path, []byte(content), 0644)

	paths, err := loadAllowedCallers(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(paths), paths)
	}
	if paths[0] != "/usr/bin/ssh" || paths[1] != "/custom/path" {
		t.Errorf("unexpected paths: %v", paths)
	}
}

func TestLoadAllowedCallers_MissingFile(t *testing.T) {
	_, err := loadAllowedCallers("/nonexistent/file")
	if err == nil {
		t.Error("expected error for missing file")
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
