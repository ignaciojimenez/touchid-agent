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

// ruleKind enumerates the ways a caller may be allowed.
type ruleKind int

const (
	// ruleApplePlatformSigningID matches a genuine Apple OS binary
	// (validated "anchor apple") whose Signing ID equals Value. This is
	// the default policy; it cannot be satisfied by third-party code.
	ruleApplePlatformSigningID ruleKind = iota
	// ruleTeamID matches an Apple-issued (Developer ID) binary whose Team
	// ID equals Value. Honored only when the signature anchors to Apple,
	// so a self-signed binary cannot claim a Team ID.
	ruleTeamID
	// ruleSigningID matches an Apple-anchored binary whose Signing ID
	// equals Value.
	ruleSigningID
	// ruleCDHash matches a binary whose code directory hash equals Value.
	// Cryptographic, so trusted regardless of signing anchor.
	ruleCDHash
	// rulePath matches by main-executable path. The escape hatch for
	// ad-hoc / unsigned callers; less secure (a user-writable path can be
	// replaced), so its use is surfaced loudly at startup.
	rulePath
)

// CallerRule is one entry in the caller allowlist.
type CallerRule struct {
	Kind  ruleKind
	Value string
}

// defaultCallerRules is the policy when none is configured: only Apple's
// platform SSH tools, matched by validated Apple-platform anchor + Signing
// ID. ssh-keygen is included because git SSH commit/tag signing connects as
// ssh-keygen. This is strictly stronger than a path allowlist — an Apple
// platform signature cannot be forged — and never matches third-party code.
var defaultCallerRules = []CallerRule{
	{ruleApplePlatformSigningID, "com.apple.ssh"},
	{ruleApplePlatformSigningID, "com.apple.scp"},
	{ruleApplePlatformSigningID, "com.apple.sftp"},
	{ruleApplePlatformSigningID, "com.apple.ssh-keygen"},
}

// matches reports whether peer satisfies this rule. Team ID / Signing ID are
// only honored for Apple-anchored signatures so a forged or self-signed
// binary cannot claim them; CDHash is cryptographic; path is unconditional.
func (r CallerRule) matches(peer Peer) bool {
	switch r.Kind {
	case ruleApplePlatformSigningID:
		return peer.ApplePlatform && peer.SigningID == r.Value
	case ruleTeamID:
		return peer.AppleAnchored && peer.TeamID == r.Value
	case ruleSigningID:
		return peer.AppleAnchored && peer.SigningID == r.Value
	case ruleCDHash:
		return peer.CDHash != "" && strings.EqualFold(peer.CDHash, r.Value)
	case rulePath:
		return pathMatches(peer.Path, r.Value)
	}
	return false
}

// pathMatches compares a peer path against an allowlisted path, resolving
// symlinks in the allowlist entry so configured symlinked paths match.
func pathMatches(peerPath, allowed string) bool {
	if peerPath == "" || allowed == "" {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(allowed); err == nil {
		return peerPath == resolved
	}
	return peerPath == allowed
}

// PeerPolicy enforces caller verification and rate limiting on signing
// operations. A nil *PeerPolicy is a valid no-op policy.
type PeerPolicy struct {
	rules     []CallerRule
	enforce   bool
	rateLimit int
	rates     sync.Map // label -> *rateBucket
}

func NewPeerPolicy(enforce bool, rateLimit int, extraRules []CallerRule) *PeerPolicy {
	if rateLimit > rateLimitCeiling {
		rateLimit = rateLimitCeiling
	}
	rules := make([]CallerRule, len(defaultCallerRules))
	copy(rules, defaultCallerRules)
	rules = append(rules, extraRules...)
	return &PeerPolicy{
		rules:     rules,
		enforce:   enforce,
		rateLimit: rateLimit,
	}
}

// pathRules returns the configured path-based rules, which authorize
// unsigned callers and are therefore worth surfacing to the operator.
func (p *PeerPolicy) pathRules() []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, r := range p.rules {
		if r.Kind == rulePath {
			out = append(out, r.Value)
		}
	}
	return out
}

// IsAllowedCaller reports whether peer satisfies any configured rule.
func (p *PeerPolicy) IsAllowedCaller(peer Peer) bool {
	if p == nil {
		return false
	}
	for _, r := range p.rules {
		if r.matches(peer) {
			return true
		}
	}
	return false
}

// CheckCaller returns an error if enforcement is enabled and the peer does
// not satisfy any configured rule.
func (p *PeerPolicy) CheckCaller(peer Peer) error {
	if p == nil || !p.enforce {
		return nil
	}
	if p.IsAllowedCaller(peer) {
		return nil
	}
	if peer.Path == "" {
		return fmt.Errorf("peer could not be identified (pid %d)", peer.PID)
	}
	return fmt.Errorf("caller not in allowlist: %s (pid %d, signing_id=%q team_id=%q signed=%v)",
		peer.Path, peer.PID, peer.SigningID, peer.TeamID, peer.Signed)
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

// loadAllowedCallers parses a caller-allowlist file into typed rules. Each
// non-comment line is one rule:
//
//	team-id:ABCDE12345          allow an Apple-anchored binary with this Team ID
//	signing-id:org.example.ssh  allow an Apple-anchored binary with this Signing ID
//	cdhash:9f86d0...            allow an exact binary by code directory hash
//	path:/opt/homebrew/bin/ssh  allow by path (ad-hoc/unsigned escape hatch)
//	/opt/homebrew/bin/ssh       bare absolute path == path rule (back-compat)
//
// For the Team ID / Signing ID / CDHash rules to mean anything against
// tampering, this file must live somewhere the caller it authorizes cannot
// rewrite — a root-owned path or one delivered via Managed Preferences.
func loadAllowedCallers(path string) ([]CallerRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open allowed callers file: %w", err)
	}
	defer f.Close()
	var rules []CallerRule
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := parseCallerRule(line)
		if err != nil {
			return nil, fmt.Errorf("allowed callers line %d: %w", lineNo, err)
		}
		rules = append(rules, rule)
	}
	return rules, scanner.Err()
}

func parseCallerRule(line string) (CallerRule, error) {
	kind, value, ok := strings.Cut(line, ":")
	if !ok {
		// No prefix: a bare absolute path (back-compat with the original
		// path-only -allowed-callers format).
		if strings.HasPrefix(line, "/") {
			return CallerRule{rulePath, line}, nil
		}
		return CallerRule{}, fmt.Errorf("unrecognized rule %q (want team-id:/signing-id:/cdhash:/path: or an absolute path)", line)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return CallerRule{}, fmt.Errorf("empty value in rule %q", line)
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "team-id", "teamid":
		return CallerRule{ruleTeamID, value}, nil
	case "signing-id", "signingid":
		return CallerRule{ruleSigningID, value}, nil
	case "cdhash":
		return CallerRule{ruleCDHash, value}, nil
	case "path":
		return CallerRule{rulePath, value}, nil
	default:
		return CallerRule{}, fmt.Errorf("unknown rule type %q", kind)
	}
}
