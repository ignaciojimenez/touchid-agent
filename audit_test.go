//go:build darwin

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestVerifyAuditChain_Intact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	for i := 0; i < 3; i++ {
		a.Sign("k", true, nil, Peer{PID: i + 1, Path: "/usr/bin/ssh"})
	}
	a.Close()

	res, err := VerifyAuditChain(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Records != 3 || res.Chained != 3 {
		t.Fatalf("intact chain: got %+v, want OK with 3 records/chained", res)
	}
}

func TestVerifyAuditChain_DetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	for i := 0; i < 3; i++ {
		a.Sign("k", true, nil, Peer{PID: i + 1, Path: "/usr/bin/ssh"})
	}
	a.Close()

	// Edit the first record; the next record's prev no longer matches.
	lines := readLines(t, path)
	lines[0] = strings.Replace(lines[0], "/usr/bin/ssh", "/usr/bin/evil", 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, _ := VerifyAuditChain(path)
	if res.OK {
		t.Fatal("tampered chain should not verify")
	}
	if res.BrokenLine != 2 {
		t.Errorf("BrokenLine = %d, want 2", res.BrokenLine)
	}
}

func TestVerifyAuditChain_DetectsDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	for i := 0; i < 4; i++ {
		a.Sign("k", true, nil, Peer{PID: i + 1})
	}
	a.Close()

	// Remove the second record.
	lines := readLines(t, path)
	kept := append([]string{lines[0]}, lines[2:]...)
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, _ := VerifyAuditChain(path)
	if res.OK {
		t.Fatal("deleted record should be detected")
	}
}

func TestVerifyAuditChain_AcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	a.Sign("k", true, nil, Peer{PID: 1})
	a.Sign("k", true, nil, Peer{PID: 2})
	a.Close()

	// New logger reopens the file and must continue the chain seamlessly.
	b, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	b.Sign("k", true, nil, Peer{PID: 3})
	b.Close()

	res, _ := VerifyAuditChain(path)
	if !res.OK || res.Chained != 3 {
		t.Fatalf("chain across restart: got %+v, want OK with 3 chained", res)
	}
}

func sshPubFromKey(t *testing.T, k *Key) ssh.PublicKey {
	t.Helper()
	pub, err := ssh.NewPublicKey(k.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

func TestAuditLogger_NilSafe(t *testing.T) {
	var a *AuditLogger
	a.Sign("anything", true, nil, Peer{})
	if err := a.Close(); err != nil {
		t.Errorf("Close on nil should be nil, got %v", err)
	}
}

func TestAuditLogger_WritesSuccessRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.Sign("ssh", true, nil, Peer{PID: 1234, UID: 501})
	a.Close()

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["event"] != "sign" || rec["label"] != "ssh" || rec["success"] != true {
		t.Errorf("unexpected record: %v", rec)
	}
	if _, ok := rec["error"]; ok {
		t.Errorf("success record should omit error, got %v", rec["error"])
	}
	if rec["peer_pid"].(float64) != 1234 || rec["peer_uid"].(float64) != 501 {
		t.Errorf("peer fields wrong: %v", rec)
	}
	if _, ok := rec["ts"].(string); !ok {
		t.Error("ts missing or not a string")
	}
}

func TestAuditLogger_WritesFailureRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	a.Sign("ssh", false, errors.New("Touch ID cancelled"), Peer{})
	a.Close()

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var rec map[string]any
	json.Unmarshal([]byte(lines[0]), &rec)
	if rec["success"] != false {
		t.Errorf("expected success=false, got %v", rec["success"])
	}
	if rec["error"] != "Touch ID cancelled" {
		t.Errorf("expected error message, got %v", rec["error"])
	}
}

func TestAuditLogger_OmitsZeroPeerFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	a.Sign("ssh", true, nil, Peer{})
	a.Close()

	rec := map[string]any{}
	lines := readLines(t, path)
	json.Unmarshal([]byte(lines[0]), &rec)
	if _, ok := rec["peer_pid"]; ok {
		t.Errorf("zero peer_pid should be omitted, got %v", rec["peer_pid"])
	}
	if _, ok := rec["peer_uid"]; ok {
		t.Errorf("zero peer_uid should be omitted, got %v", rec["peer_uid"])
	}
}

func TestAuditLogger_WritesCallerIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	a.Sign("sign", true, nil, Peer{
		PID: 5, UID: 501, Path: "/usr/bin/ssh-keygen",
		TeamID: "ABC1234567", SigningID: "com.apple.ssh-keygen",
		CDHash: "deadbeef", Signed: true,
	})
	a.Close()

	rec := map[string]any{}
	if err := json.Unmarshal([]byte(readLines(t, path)[0]), &rec); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"peer_team_id":    "ABC1234567",
		"peer_signing_id": "com.apple.ssh-keygen",
		"peer_cdhash":     "deadbeef",
		"peer_signed":     true,
	} {
		if rec[k] != want {
			t.Errorf("%s = %v, want %v", k, rec[k], want)
		}
	}
}

func TestAuditLogger_OmitsZeroCallerIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	a.Sign("ssh", true, nil, Peer{PID: 5, UID: 501, Path: "/usr/bin/ssh"})
	a.Close()

	rec := map[string]any{}
	if err := json.Unmarshal([]byte(readLines(t, path)[0]), &rec); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"peer_team_id", "peer_signing_id", "peer_cdhash", "peer_signed"} {
		if _, ok := rec[k]; ok {
			t.Errorf("empty %s should be omitted, got %v", k, rec[k])
		}
	}
}

func TestAuditLogger_AppendsToExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	a.Sign("first", true, nil, Peer{})
	a.Close()

	b, _ := NewAuditLogger(path)
	b.Sign("second", true, nil, Peer{})
	b.Close()

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines after re-open, got %d", len(lines))
	}
}

func TestAuditLogger_PermissionsAre0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)
	defer a.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("audit log perm = %o, want 0600", perm)
	}
}

func TestAuditLogger_ConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, _ := NewAuditLogger(path)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Sign("ssh", true, nil, Peer{PID: 1, UID: 1})
		}()
	}
	wg.Wait()
	a.Close()

	lines := readLines(t, path)
	if len(lines) != 50 {
		t.Errorf("expected 50 lines, got %d", len(lines))
	}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestAuditLogger_OpenFailsForUnwritablePath(t *testing.T) {
	_, err := NewAuditLogger("/nonexistent/dir/audit.log")
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestAuditLogger_CreatesParentDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs", "nested")
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer a.Close()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("parent dir not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("audit dir perm = %o, want 0700", perm)
	}
}

func TestAgent_AuditLog_OnSignSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()

	store := NewMockKeyStore()
	a := &Agent{store: store, audit: audit}

	key, _ := store.Generate("auditkey", false)
	pub := sshPubFromKey(t, key)

	if _, err := a.Sign(pub, []byte("digest-bytes-32-chars-long-paddpd")); err != nil {
		t.Fatal(err)
	}
	audit.Close()

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit line, got %d: %v", len(lines), lines)
	}
	var rec map[string]any
	json.Unmarshal([]byte(lines[0]), &rec)
	if rec["label"] != "auditkey" || rec["success"] != true {
		t.Errorf("unexpected record: %v", rec)
	}
}

func TestAgent_AuditLog_OnSignFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, _ := NewAuditLogger(path)
	defer audit.Close()

	store := NewMockKeyStore()
	a := &Agent{store: store, audit: audit}

	// Generate a key but ask the agent to sign with a *different* key —
	// this exercises the "no matching key found" branch which does not
	// hit the signing code path, and therefore should NOT emit an audit
	// record (we only audit attempts that reach a matched key).
	store.Generate("present", false)
	otherStore := NewMockKeyStore()
	other, _ := otherStore.Generate("absent", false)
	otherPub := sshPubFromKey(t, other)

	if _, err := a.Sign(otherPub, make([]byte, 32)); err == nil {
		t.Fatal("expected no-matching-key error")
	}
	audit.Close()

	lines := readLines(t, path)
	if len(lines) != 0 {
		t.Errorf("expected 0 audit lines for unmatched key, got %d: %v", len(lines), lines)
	}
}
