//go:build darwin

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"
)

type MockKeyStore struct {
	mu   sync.Mutex
	keys map[string]*Key
}

func NewMockKeyStore() *MockKeyStore {
	return &MockKeyStore{keys: make(map[string]*Key)}
}

func (m *MockKeyStore) List() ([]*Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []*Key
	for _, k := range m.keys {
		result = append(result, k)
	}
	return result, nil
}

func (m *MockKeyStore) Generate(label string, requireTouch bool) (*Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[label]; exists {
		return nil, fmt.Errorf("key already exists: %s", label)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	key := &Key{
		Label:        label,
		RequireTouch: requireTouch,
		publicKey:    &priv.PublicKey,
		signFn: func(_ string, digest []byte) ([]byte, error) {
			return ecdsa.SignASN1(rand.Reader, priv, digest)
		},
	}
	m.keys[label] = key
	return key, nil
}

func (m *MockKeyStore) Delete(label string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, label)
	return nil
}

func (m *MockKeyStore) DeleteAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = make(map[string]*Key)
	return nil
}
