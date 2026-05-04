//go:build darwin

package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const keyfileVersion = 1

type keyfile struct {
	Version      int    `json:"version"`
	Label        string `json:"label"`
	Backend      string `json:"backend"`
	RequireTouch bool   `json:"require_touch"`
	CreatedAt    string `json:"created_at"`
	KeyData      string `json:"key_data"`
	PublicKey    string `json:"public_key"`
}

type FilesystemKeyStore struct {
	Dir string
}

func DefaultKeyStore() (*FilesystemKeyStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	root := filepath.Join(home, ".touchid-agent")
	dir := filepath.Join(root, "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	// Defensive: tighten perms on both layers in case the dir pre-existed
	// with a looser umask. Failures here are not fatal - readability already
	// requires UID match.
	_ = os.Chmod(root, 0o700)
	_ = os.Chmod(dir, 0o700)
	return &FilesystemKeyStore{Dir: dir}, nil
}

func (s *FilesystemKeyStore) path(label string) string {
	return filepath.Join(s.Dir, label+".json")
}

func (s *FilesystemKeyStore) Generate(label string, requireTouch, useSE bool) (*SEKey, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	path := s.path(label)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("key %q already exists at %s", label, path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	var (
		backend Backend
		keyData []byte
		pub     *ecdsa.PublicKey
		err     error
	)
	if useSE {
		backend = BackendSecureEnclave
		keyData, pub, err = generateSEKey(requireTouch)
	} else {
		if !softwareBackendEnabled {
			return nil, errors.New("software backend is disabled in this build")
		}
		backend = BackendSoftware
		keyData, pub, err = generateSoftwareKey()
	}
	if err != nil {
		return nil, err
	}

	keyDataForFile := base64.StdEncoding.EncodeToString(keyData)
	if backend == BackendSoftware {
		if err := keychainStore(label, keyData); err != nil {
			return nil, fmt.Errorf("keychain store: %w", err)
		}
		keyDataForFile = ""
	}

	rec := keyfile{
		Version:      keyfileVersion,
		Label:        label,
		Backend:      backend.String(),
		RequireTouch: requireTouch,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		KeyData:      keyDataForFile,
		PublicKey:    base64.StdEncoding.EncodeToString(marshalECPublicKey(pub)),
	}
	if err := writeKeyfile(path, &rec); err != nil {
		return nil, err
	}

	return &SEKey{
		Label:        label,
		Backend:      backend,
		RequireTouch: requireTouch,
		publicKey:    pub,
		keyData:      keyData,
	}, nil
}

func (s *FilesystemKeyStore) List() ([]*SEKey, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.Dir, err)
	}
	var keys []*SEKey
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		key, err := loadKeyfile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			log.Printf("skipping %s: %v", e.Name(), err)
			continue
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Label < keys[j].Label })
	return keys, nil
}

func (s *FilesystemKeyStore) Delete(label string) error {
	if err := validateLabel(label); err != nil {
		return err
	}
	_ = keychainDelete(label)
	err := os.Remove(s.path(label))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (s *FilesystemKeyStore) DeleteAll() error {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	var firstErr error
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		label := strings.TrimSuffix(e.Name(), ".json")
		_ = keychainDelete(label)
		if err := os.Remove(filepath.Join(s.Dir, e.Name())); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// MigrateToKeychain moves software key material from on-disk JSON files into the
// macOS Keychain. Intended to be run as a one-shot CLI command, not concurrently
// with the agent daemon.
func (s *FilesystemKeyStore) MigrateToKeychain() (int, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return 0, err
	}
	migrated := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.Dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("skipping %s: %v", e.Name(), err)
			continue
		}
		var rec keyfile
		if err := json.Unmarshal(data, &rec); err != nil {
			log.Printf("skipping %s: %v", e.Name(), err)
			continue
		}
		backend, err := parseBackend(rec.Backend)
		if err != nil || backend != BackendSoftware || rec.KeyData == "" {
			continue
		}
		keyData, err := base64.StdEncoding.DecodeString(rec.KeyData)
		if err != nil || len(keyData) == 0 {
			continue
		}
		if err := migrateKeyToKeychain(path, &rec, keyData); err != nil {
			return migrated, fmt.Errorf("migrate %q: %w", rec.Label, err)
		}
		log.Printf("migrated %s to Keychain", rec.Label)
		migrated++
	}
	return migrated, nil
}

func migrateKeyToKeychain(path string, rec *keyfile, keyData []byte) error {
	if err := keychainStore(rec.Label, keyData); err != nil {
		return err
	}
	rec.KeyData = ""
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func writeKeyfile(path string, rec *keyfile) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rec); err != nil {
		os.Remove(path)
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return nil
}

func loadKeyfile(path string) (*SEKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec keyfile
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	if rec.Version != keyfileVersion {
		return nil, fmt.Errorf("unsupported version %d", rec.Version)
	}
	if rec.Label != strings.TrimSuffix(filepath.Base(path), ".json") {
		return nil, fmt.Errorf("label %q does not match filename", rec.Label)
	}
	backend, err := parseBackend(rec.Backend)
	if err != nil {
		return nil, err
	}
	if backend == BackendSoftware && !softwareBackendEnabled {
		return nil, fmt.Errorf("software key %q not supported in this build", rec.Label)
	}
	var keyData []byte
	if backend == BackendSoftware && rec.KeyData == "" {
		keyData, err = keychainLoad(rec.Label)
		if err != nil {
			return nil, fmt.Errorf("keychain load for %q: %w", rec.Label, err)
		}
	} else {
		keyData, err = base64.StdEncoding.DecodeString(rec.KeyData)
		if err != nil {
			return nil, fmt.Errorf("decode key_data: %w", err)
		}
		if backend == BackendSoftware && len(keyData) > 0 {
			log.Printf("warning: software key %q has unprotected key material on disk; run -migrate to move it to the Keychain", rec.Label)
		}
	}
	pubRaw, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public_key: %w", err)
	}
	pub, err := parseECPublicKey(pubRaw)
	if err != nil {
		return nil, err
	}
	return &SEKey{
		Label:        rec.Label,
		Backend:      backend,
		RequireTouch: rec.RequireTouch,
		publicKey:    pub,
		keyData:      keyData,
	}, nil
}
