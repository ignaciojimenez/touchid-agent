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
	keys map[string]*SEKey
}

func NewMockKeyStore() *MockKeyStore {
	return &MockKeyStore{keys: make(map[string]*SEKey)}
}

func (m *MockKeyStore) List() ([]*SEKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []*SEKey
	for _, k := range m.keys {
		result = append(result, k)
	}
	return result, nil
}

func (m *MockKeyStore) Generate(label string, requireTouch bool, _ bool) (*SEKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tag := makeTag(label, requireTouch)
	if _, exists := m.keys[tag]; exists {
		return nil, fmt.Errorf("key already exists: %s", label)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	key := &SEKey{
		Label:        label,
		Tag:          tag,
		RequireTouch: requireTouch,
		publicKey:    &priv.PublicKey,
		signFn: func(_ string, digest []byte) ([]byte, error) {
			return ecdsa.SignASN1(rand.Reader, priv, digest)
		},
	}
	m.keys[tag] = key
	return key, nil
}

func (m *MockKeyStore) Delete(label string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, touch := range []bool{true, false} {
		tag := makeTag(label, touch)
		delete(m.keys, tag)
	}
	return nil
}

func (m *MockKeyStore) DeleteAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys = make(map[string]*SEKey)
	return nil
}
