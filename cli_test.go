//go:build darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateLabel_Valid(t *testing.T) {
	valid := []string{"ssh", "git", "my-key", "key_1", "a"}
	for _, label := range valid {
		if err := validateLabel(label); err != nil {
			t.Errorf("validateLabel(%q) = %v, want nil", label, err)
		}
	}
}

func TestValidateLabel_Empty(t *testing.T) {
	err := validateLabel("")
	if err == nil {
		t.Error("validateLabel(\"\") should return error")
	}
}

func TestValidateLabel_WithColon(t *testing.T) {
	err := validateLabel("my:key")
	if err == nil {
		t.Error("validateLabel with colon should return error")
	}
}

func TestValidateLabel_WithSlash(t *testing.T) {
	err := validateLabel("my/key")
	if err == nil {
		t.Error("validateLabel with slash should return error")
	}
}

func TestValidateLabel_WithBackslash(t *testing.T) {
	err := validateLabel("my\\key")
	if err == nil {
		t.Error("validateLabel with backslash should return error")
	}
}

func TestValidateLabel_TooLong(t *testing.T) {
	long := strings.Repeat("a", 65)
	err := validateLabel(long)
	if err == nil {
		t.Error("validateLabel with >64 chars should return error")
	}
}

func TestValidateLabel_MaxLength(t *testing.T) {
	exact := strings.Repeat("a", 64)
	if err := validateLabel(exact); err != nil {
		t.Errorf("validateLabel with exactly 64 chars should succeed: %v", err)
	}
}

func TestValidateLabel_SpecialChars(t *testing.T) {
	valid := []string{"key-with-dashes", "key_with_underscores", "Key123", "KEY"}
	for _, label := range valid {
		if err := validateLabel(label); err != nil {
			t.Errorf("validateLabel(%q) = %v, want nil", label, err)
		}
	}
}

func TestRemovePubKeyFile_RemovesFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)
	pubFile := filepath.Join(sshDir, "touchid-agent-ssh.pub")
	os.WriteFile(pubFile, []byte("ecdsa-sha2-nistp256 AAAA touchid-agent:ssh\n"), 0644)

	removePubKeyFile("ssh")

	if _, err := os.Stat(pubFile); !os.IsNotExist(err) {
		t.Errorf("pub key file should be removed, stat = %v", err)
	}
}

func TestRemovePubKeyFile_NoopWhenMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Should not panic or log an error for a non-existent file.
	removePubKeyFile("ghost")
}

func TestCmdDelete_RemovesPubKeyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)
	pubFile := filepath.Join(sshDir, "touchid-agent-delme.pub")
	os.WriteFile(pubFile, []byte("ecdsa-sha2-nistp256 AAAA touchid-agent:delme\n"), 0644)

	dir := t.TempDir()
	writeTestKeyfile(t, dir, "delme", false)
	store := &FilesystemKeyStore{Dir: dir}

	cmdDelete(store, "delme")

	if _, err := os.Stat(pubFile); !os.IsNotExist(err) {
		t.Errorf("cmdDelete should remove pub key file, stat = %v", err)
	}
}

func TestCmdDeleteAll_RemovesPubKeyFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)

	store := NewMockKeyStore()
	for _, label := range []string{"a", "b"} {
		store.Generate(label, false)
		pubFile := filepath.Join(sshDir, "touchid-agent-"+label+".pub")
		os.WriteFile(pubFile, []byte("fake-key\n"), 0644)
	}

	cmdDeleteAll(store, []string{"a", "b"})

	for _, label := range []string{"a", "b"} {
		pubFile := filepath.Join(sshDir, "touchid-agent-"+label+".pub")
		if _, err := os.Stat(pubFile); !os.IsNotExist(err) {
			t.Errorf("pub key file for %q should be removed, stat = %v", label, err)
		}
	}
}

func TestCmdList_JSON(t *testing.T) {
	store := NewMockKeyStore()
	store.Generate("ssh", true)
	store.Generate("git", false)

	// Capture stdout.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	cmdList(store, true)

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	var entries []keyListEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, output)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	byLabel := map[string]keyListEntry{}
	for _, e := range entries {
		byLabel[e.Label] = e
	}
	if e, ok := byLabel["ssh"]; !ok || !e.RequireTouch {
		t.Errorf("ssh key should have require_touch=true, got %+v", byLabel["ssh"])
	}
	if e, ok := byLabel["git"]; !ok || e.RequireTouch {
		t.Errorf("git key should have require_touch=false, got %+v", byLabel["git"])
	}
	for _, e := range entries {
		if e.PublicKey == "" {
			t.Errorf("key %q has empty public_key", e.Label)
		}
	}
}

func TestCmdList_JSON_Empty(t *testing.T) {
	store := NewMockKeyStore()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	cmdList(store, true)

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := strings.TrimSpace(buf.String())

	if output != "[]" {
		t.Errorf("empty list should output [], got %q", output)
	}
}

func TestClassifySignError(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		notWant string
	}{
		{"user cancel", "LAError -2: userCancel", "cancelled", "bug"},
		{"biometry not available", "LAError -6: biometryNotAvailable", "not available", ""},
		{"biometry not enrolled", "LAError -7: biometryNotEnrolled", "enroll", ""},
		{"biometry lockout", "LAError -8: biometryLockout", "locked out", ""},
		{"passcode not set", "LAError -4: passcodeNotSet", "password", ""},
		{"unknown error", "some random CryptoKit error", "sign:", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifySignError(errors.New(tc.input))
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("classifySignError(%q) = %q, want substring %q", tc.input, err.Error(), tc.want)
			}
			if tc.notWant != "" && strings.Contains(err.Error(), tc.notWant) {
				t.Errorf("classifySignError(%q) = %q, should not contain %q", tc.input, err.Error(), tc.notWant)
			}
		})
	}
}
