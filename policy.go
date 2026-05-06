//go:build darwin

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const rateLimitCeiling = 120

var defaultAllowedCallers = []string{
	"/usr/bin/ssh",
	"/usr/bin/scp",
	"/usr/bin/sftp",
	"/opt/homebrew/bin/ssh",
	"/opt/homebrew/bin/scp",
	"/opt/homebrew/bin/sftp",
	"/usr/local/bin/ssh",
	"/usr/local/bin/scp",
	"/usr/local/bin/sftp",
}

// PeerPolicy enforces caller verification and rate limiting on signing
// operations. A nil *PeerPolicy is a valid no-op policy.
type PeerPolicy struct {
	allowedPaths []string
	enforce      bool
	rateLimit    int
	rates        sync.Map // label -> *rateBucket
}

func NewPeerPolicy(enforce bool, rateLimit int, extraCallers []string) *PeerPolicy {
	if rateLimit > rateLimitCeiling {
		rateLimit = rateLimitCeiling
	}
	paths := make([]string, len(defaultAllowedCallers))
	copy(paths, defaultAllowedCallers)
	paths = append(paths, extraCallers...)
	return &PeerPolicy{
		allowedPaths: paths,
		enforce:      enforce,
		rateLimit:    rateLimit,
	}
}

// IsAllowedCaller checks whether the given binary path matches an
// entry in the allowlist. Symlinks in the allowlist are resolved at
// check time so that Homebrew Cellar paths match correctly.
func (p *PeerPolicy) IsAllowedCaller(peerPath string) bool {
	if p == nil || peerPath == "" {
		return false
	}
	for _, allowed := range p.allowedPaths {
		resolved, err := filepath.EvalSymlinks(allowed)
		if err != nil {
			if allowed == peerPath {
				return true
			}
			continue
		}
		if peerPath == resolved {
			return true
		}
	}
	return false
}

// CheckCaller returns an error if enforcement is enabled and the peer
// binary is not in the allowlist. Touch-ID-gated keys should skip this
// check since biometry already protects them.
func (p *PeerPolicy) CheckCaller(peer Peer) error {
	if p == nil || !p.enforce {
		return nil
	}
	if p.IsAllowedCaller(peer.Path) {
		return nil
	}
	if peer.Path == "" {
		return fmt.Errorf("peer binary could not be identified (pid %d)", peer.PID)
	}
	return fmt.Errorf("peer binary not in allowlist: %s (pid %d)", peer.Path, peer.PID)
}

// CheckRate returns an error if the per-key signing rate has been
// exceeded. A zero rateLimit disables rate limiting.
func (p *PeerPolicy) CheckRate(label string) error {
	if p == nil || p.rateLimit <= 0 {
		return nil
	}
	v, _ := p.rates.LoadOrStore(label, &rateBucket{})
	b := v.(*rateBucket)
	if !b.allow(p.rateLimit) {
		return fmt.Errorf("rate limit exceeded (%d/min)", p.rateLimit)
	}
	return nil
}

type rateBucket struct {
	mu    sync.Mutex
	times []time.Time
}

func (b *rateBucket) allow(limit int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	valid := b.times[:0]
	for _, t := range b.times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	b.times = valid
	if len(b.times) >= limit {
		return false
	}
	b.times = append(b.times, now)
	return true
}

func loadAllowedCallers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open allowed callers file: %w", err)
	}
	defer f.Close()
	var paths []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		paths = append(paths, line)
	}
	return paths, scanner.Err()
}
