//go:build darwin

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// genesisPrev is the prev-hash of the first record in a chain.
const genesisPrev = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditLogger writes one JSON object per line for each signing event. Records
// are hash-chained: each carries a monotonic seq and the SHA-256 of the
// previous record's bytes (prev), so modification, reordering, or deletion of
// earlier records is detectable with `-verify-audit`. The chain is tamper-
// evident, not tamper-proof — a same-UID attacker who can write the file can
// recompute it; durable tamper-resistance comes from shipping the log off-host.
// A nil *AuditLogger is a valid no-op logger.
type AuditLogger struct {
	mu       sync.Mutex
	w        io.Writer
	closer   io.Closer
	seq      uint64
	prevHash string
}

func NewAuditLogger(path string) (*AuditLogger, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create audit log dir %s: %w", dir, err)
		}
	}
	// Continue an existing chain across restarts (launchd respawns the agent
	// often) by seeding seq and prev from the last record already on disk.
	seq, prev := seedChain(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	return &AuditLogger{w: f, closer: f, seq: seq, prevHash: prev}, nil
}

func NewStderrAuditLogger() *AuditLogger {
	return &AuditLogger{w: os.Stderr, closer: nopCloser{}, prevHash: genesisPrev}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// seedChain returns the seq and prev-hash needed to continue the chain in an
// existing log file. For a new or empty file it returns (0, genesis).
func seedChain(path string) (uint64, string) {
	last := readLastLine(path)
	if len(last) == 0 {
		return 0, genesisPrev
	}
	var rec struct {
		Seq uint64 `json:"seq"`
	}
	_ = json.Unmarshal(last, &rec)
	return rec.Seq, hashLine(last)
}

// readLastLine returns the last newline-delimited line of a file (without the
// trailing newline), reading only the tail. Empty if the file is missing/empty.
func readLastLine(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return nil
	}
	const tail = 1 << 16
	start := fi.Size() - tail
	if start < 0 {
		start = 0
	}
	buf := make([]byte, fi.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return nil
	}
	for len(buf) > 0 && buf[len(buf)-1] == '\n' {
		buf = buf[:len(buf)-1]
	}
	for i := len(buf) - 1; i >= 0; i-- {
		if buf[i] == '\n' {
			return buf[i+1:]
		}
	}
	return buf
}

func hashLine(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

const eventSign = "sign"

type signEvent struct {
	Timestamp string `json:"ts"`
	Event     string `json:"event"`
	Seq       uint64 `json:"seq"`
	Prev      string `json:"prev"`
	Label     string `json:"label"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	PeerPID   int    `json:"peer_pid,omitempty"`
	PeerUID   uint32 `json:"peer_uid,omitempty"`
	PeerPath  string `json:"peer_path,omitempty"`

	// Code-signing identity of the caller, resolved from the audit token.
	PeerTeamID    string `json:"peer_team_id,omitempty"`
	PeerSigningID string `json:"peer_signing_id,omitempty"`
	PeerCDHash    string `json:"peer_cdhash,omitempty"`
	PeerSigned    bool   `json:"peer_signed,omitempty"`
}

func (a *AuditLogger) Sign(label string, success bool, err error, peer Peer) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	rec := signEvent{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Event:         eventSign,
		Seq:           a.seq + 1,
		Prev:          a.prevHash,
		Label:         label,
		Success:       success,
		PeerPID:       peer.PID,
		PeerUID:       peer.UID,
		PeerPath:      peer.Path,
		PeerTeamID:    peer.TeamID,
		PeerSigningID: peer.SigningID,
		PeerCDHash:    peer.CDHash,
		PeerSigned:    peer.Signed,
	}
	if err != nil {
		rec.Error = err.Error()
	}
	line, mErr := json.Marshal(rec)
	if mErr != nil {
		fmt.Fprintf(os.Stderr, "audit: marshal failed: %v\n", mErr)
		return
	}
	// Write the line and its newline as one buffer; keep `line` pristine so its
	// hash matches the bytes a verifier reads back.
	out := make([]byte, 0, len(line)+1)
	out = append(out, line...)
	out = append(out, '\n')
	if _, wErr := a.w.Write(out); wErr != nil {
		// Surface to stderr but keep serving — the audit log failing must
		// never break SSH for the user.
		fmt.Fprintf(os.Stderr, "audit: write failed: %v\n", wErr)
		return
	}
	a.seq = rec.Seq
	a.prevHash = hashLine(line)
}

func (a *AuditLogger) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closer.Close()
}

// VerifyResult summarizes an audit-chain verification.
type VerifyResult struct {
	Records    int    // total lines read
	Chained    int    // records carrying a prev hash (i.e. chain-protected)
	OK         bool   // true if the chain is intact
	BrokenLine int    // 1-based line of the first failure (0 if OK)
	Reason     string // explanation
}

// VerifyAuditChain walks the hash chain in an audit log and reports the first
// break — a modified, reordered, or deleted record. Records with no prev field
// (legacy, pre-chain) are not checked but still advance the running hash.
func VerifyAuditChain(path string) (VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return VerifyResult{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	expectedPrev := genesisPrev
	var expectedSeq uint64
	var records, chained, line int
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		line++
		records = line
		var rec struct {
			Seq  uint64 `json:"seq"`
			Prev string `json:"prev"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return VerifyResult{Records: records, BrokenLine: line, Reason: fmt.Sprintf("invalid JSON: %v", err)}, nil
		}
		if rec.Prev != "" {
			if rec.Prev != expectedPrev {
				return VerifyResult{Records: records, Chained: chained, BrokenLine: line,
					Reason: "prev-hash mismatch — an earlier record was modified, reordered, or removed"}, nil
			}
			if expectedSeq != 0 && rec.Seq != expectedSeq+1 {
				return VerifyResult{Records: records, Chained: chained, BrokenLine: line,
					Reason: fmt.Sprintf("seq gap (expected %d, got %d) — a record was inserted or removed", expectedSeq+1, rec.Seq)}, nil
			}
			expectedSeq = rec.Seq
			chained++
		}
		expectedPrev = hashLine(raw) // hash the exact bytes on disk
	}
	if err := sc.Err(); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Records: records, Chained: chained, OK: true}, nil
}
