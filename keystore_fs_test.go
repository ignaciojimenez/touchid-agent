//go:build darwin

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeTestKeyfile drops a valid keyfile JSON for an ad-hoc software key into
// the store directory. Lets us exercise List/Delete/DeleteAll without going
// near the SEP.
func writeTestKeyfile(t *testing.T, dir, label string, requireTouch bool, backend Backend) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec := keyfile{
		Version:      keyfileVersion,
		Label:        label,
		Backend:      backend.String(),
		RequireTouch: requireTouch,
		CreatedAt:    "2026-01-01T00:00:00Z",
		KeyData:      base64.StdEncoding.EncodeToString(priv.D.Bytes()),
		PublicKey:    base64.StdEncoding.EncodeToString(marshalECPublicKey(&priv.PublicKey)),
	}
	path := filepath.Join(dir, label+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(rec); err != nil {
		t.Fatal(err)
	}
}

func TestFilesystemKeyStore_ListEmpty(t *testing.T) {
	s := &FilesystemKeyStore{Dir: t.TempDir()}
	keys, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestFilesystemKeyStore_ListMissingDir(t *testing.T) {
	s := &FilesystemKeyStore{Dir: filepath.Join(t.TempDir(), "does-not-exist")}
	keys, err := s.List()
	if err != nil {
		t.Fatalf("missing dir should be a soft empty, got %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestFilesystemKeyStore_ListMultipleSorted(t *testing.T) {
	dir := t.TempDir()
	writeTestKeyfile(t, dir, "zeta", true, BackendSecureEnclave)
	writeTestKeyfile(t, dir, "alpha", false, BackendSoftware)
	writeTestKeyfile(t, dir, "mu", true, BackendSecureEnclave)

	s := &FilesystemKeyStore{Dir: dir}
	keys, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	// Stable sort by label keeps -list output deterministic.
	want := []string{"alpha", "mu", "zeta"}
	for i, k := range keys {
		if k.Label != want[i] {
			t.Errorf("keys[%d].Label = %q, want %q", i, k.Label, want[i])
		}
	}
}

func TestFilesystemKeyStore_ListSkipsMalformed(t *testing.T) {
	dir := t.TempDir()
	writeTestKeyfile(t, dir, "good", true, BackendSecureEnclave)
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("scratch"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &FilesystemKeyStore{Dir: dir}
	keys, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Label != "good" {
		t.Fatalf("expected only 'good', got %+v", keys)
	}
}

func TestFilesystemKeyStore_ListRejectsLabelMismatch(t *testing.T) {
	dir := t.TempDir()
	// Keyfile claims label "claimed" but is stored as renamed.json - load
	// must reject this (defends against directory traversal and stale
	// filenames after a manual rename).
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rec := keyfile{
		Version:      keyfileVersion,
		Label:        "claimed",
		Backend:      BackendSoftware.String(),
		RequireTouch: false,
		CreatedAt:    "2026-01-01T00:00:00Z",
		KeyData:      base64.StdEncoding.EncodeToString(priv.D.Bytes()),
		PublicKey:    base64.StdEncoding.EncodeToString(marshalECPublicKey(&priv.PublicKey)),
	}
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(dir, "renamed.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &FilesystemKeyStore{Dir: dir}
	keys, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("label-mismatch file should be skipped, got %+v", keys)
	}
}

func TestFilesystemKeyStore_DeleteIdempotent(t *testing.T) {
	s := &FilesystemKeyStore{Dir: t.TempDir()}
	// Deleting a key that does not exist must succeed (idempotent CLI).
	if err := s.Delete("ghost"); err != nil {
		t.Errorf("Delete on missing key should be nil, got %v", err)
	}
}

func TestFilesystemKeyStore_DeleteRemovesFile(t *testing.T) {
	dir := t.TempDir()
	writeTestKeyfile(t, dir, "victim", true, BackendSecureEnclave)
	s := &FilesystemKeyStore{Dir: dir}

	if err := s.Delete("victim"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "victim.json")); !os.IsNotExist(err) {
		t.Errorf("file should be removed, stat = %v", err)
	}
}

func TestFilesystemKeyStore_DeleteAll(t *testing.T) {
	dir := t.TempDir()
	writeTestKeyfile(t, dir, "a", true, BackendSecureEnclave)
	writeTestKeyfile(t, dir, "b", false, BackendSoftware)
	// Foreign file - must be left alone.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &FilesystemKeyStore{Dir: dir}
	if err := s.DeleteAll(); err != nil {
		t.Fatal(err)
	}

	keys, _ := s.List()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys after DeleteAll, got %d", len(keys))
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Errorf("foreign file should survive DeleteAll, got %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("dir itself should survive DeleteAll, got %v", err)
	}
}

func TestFilesystemKeyStore_GenerateRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	writeTestKeyfile(t, dir, "taken", true, BackendSecureEnclave)
	s := &FilesystemKeyStore{Dir: dir}

	// useSE=true would normally trigger an SE call, but the existence
	// check fires first - so this exercises the collision path without
	// ever touching the SEP.
	_, err := s.Generate("taken", true, true)
	if err == nil {
		t.Fatal("expected error for existing label")
	}
}

func TestFilesystemKeyStore_DefaultKeyStoreInitialises(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	s, err := DefaultKeyStore()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("keys dir perm = %o, want 0700", perm)
	}
	parent := filepath.Dir(s.Dir)
	pinfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if perm := pinfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("parent dir perm = %o, want 0700", perm)
	}
}

func TestFilesystemKeyStore_GenerateMissingDirIsAnError(t *testing.T) {
	// Generate against a non-existent dir surfaces the OS error rather
	// than silently MkdirAll'ing - DefaultKeyStore is the only blessed
	// path that should be creating directories.
	s := &FilesystemKeyStore{Dir: filepath.Join(t.TempDir(), "missing")}
	_, err := s.Generate("k", true, true)
	if err == nil {
		t.Fatal("expected error generating into missing dir")
	}
}
