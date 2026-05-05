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
// A nil *AuditLogger is a valid no-op logger, so callers don't need a
// nil check before every event.
type AuditLogger struct {
	mu     sync.Mutex
	enc    *json.Encoder
	closer io.Closer
}

func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	return &AuditLogger{enc: json.NewEncoder(f), closer: f}, nil
}

// Peer captures local socket peer credentials. Zero values mean the
// credentials could not be determined; they are still safe to log
// (omitempty drops them from the JSON record).
type Peer struct {
	PID int
	UID uint32
}

const eventSign = "sign"

type signEvent struct {
	Timestamp string `json:"ts"`
	Event     string `json:"event"`
	Label     string `json:"label"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	PeerPID   int    `json:"peer_pid,omitempty"`
	PeerUID   uint32 `json:"peer_uid,omitempty"`
}

func (a *AuditLogger) Sign(label string, success bool, err error, peer Peer) {
	if a == nil {
		return
	}
	rec := signEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Event:     eventSign,
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
		// Surface to stderr but keep serving — the audit log failing
		// must never break SSH for the user.
		fmt.Fprintf(os.Stderr, "audit: write failed: %v\n", encErr)
	}
}

func (a *AuditLogger) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closer.Close()
}
