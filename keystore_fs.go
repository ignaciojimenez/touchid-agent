//go:build darwin

package main

import (
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

type KeyStore interface {
	List() ([]*Key, error)
	Generate(label string, requireTouch bool) (*Key, error)
	Delete(label string) error
	DeleteAll() error
}

const keyfileVersion = 1

type keyfile struct {
	Version      int    `json:"version"`
	Label        string `json:"label"`
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
	_ = os.Chmod(root, 0o700)
	_ = os.Chmod(dir, 0o700)
	return &FilesystemKeyStore{Dir: dir}, nil
}

func (s *FilesystemKeyStore) path(label string) string {
	return filepath.Join(s.Dir, label+".json")
}

func (s *FilesystemKeyStore) Generate(label string, requireTouch bool) (*Key, error) {
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	path := s.path(label)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("key %q already exists at %s", label, path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	keyData, pub, err := generateSEKey(requireTouch)
	if err != nil {
		return nil, err
	}

	rec := keyfile{
		Version:      keyfileVersion,
		Label:        label,
		RequireTouch: requireTouch,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		KeyData:      base64.StdEncoding.EncodeToString(keyData),
		PublicKey:    base64.StdEncoding.EncodeToString(marshalECPublicKey(pub)),
	}
	if err := writeKeyfile(path, &rec); err != nil {
		return nil, err
	}

	return &Key{
		Label:        label,
		RequireTouch: requireTouch,
		publicKey:    pub,
		keyData:      keyData,
	}, nil
}

func (s *FilesystemKeyStore) List() ([]*Key, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.Dir, err)
	}
	var keys []*Key
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
		if err := os.Remove(filepath.Join(s.Dir, e.Name())); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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

func loadKeyfile(path string) (*Key, error) {
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
	keyData, err := base64.StdEncoding.DecodeString(rec.KeyData)
	if err != nil {
		return nil, fmt.Errorf("decode key_data: %w", err)
	}
	pubRaw, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public_key: %w", err)
	}
	pub, err := parseECPublicKey(pubRaw)
	if err != nil {
		return nil, err
	}
	return &Key{
		Label:        rec.Label,
		RequireTouch: rec.RequireTouch,
		publicKey:    pub,
		keyData:      keyData,
	}, nil
}
