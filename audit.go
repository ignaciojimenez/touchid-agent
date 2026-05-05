//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// AuditLogger writes one JSON object per line for each signing event.
// A nil *AuditLogger is a valid no-op logger so callers do not need to
// check before invoking it.
type AuditLogger struct {
	mu     sync.Mutex
	enc    *json.Encoder
	closer io.Closer
}

// NewAuditLogger opens path for appending and returns a logger ready to
// receive events. Mode is 0600 (owner-only). The file is created if it
// does not exist.
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	return &AuditLogger{enc: json.NewEncoder(f), closer: f}, nil
}

// Peer captures the credentials of the local socket peer. Zero values
// mean the credentials could not be determined (e.g. the connection is
// not a Unix socket, or the syscall failed); they are still safe to log.
type Peer struct {
	PID int
	UID uint32
}

type signEvent struct {
	Timestamp string `json:"ts"`
	Event     string `json:"event"`
	Label     string `json:"label"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	PeerPID   int    `json:"peer_pid,omitempty"`
	PeerUID   uint32 `json:"peer_uid,omitempty"`
}

// Sign records a signing attempt. Safe to call on a nil *AuditLogger.
func (a *AuditLogger) Sign(label string, success bool, err error, peer Peer) {
	if a == nil {
		return
	}
	rec := signEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Event:     "sign",
		Label:     label,
		Success:   success,
		PeerPID:   peer.PID,
		PeerUID:   peer.UID,
	}
	if err != nil {
		rec.Error = err.Error()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if encErr := a.enc.Encode(rec); encErr != nil {
		// Audit-log write failure is operationally bad but must not
		// break SSH for the user. Surface to stderr; the daemon
		// continues to serve.
		fmt.Fprintf(os.Stderr, "audit: write failed: %v\n", encErr)
	}
}

// Close flushes and closes the underlying file. Safe to call on nil.
func (a *AuditLogger) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closer.Close()
}
