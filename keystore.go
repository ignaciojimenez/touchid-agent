//go:build darwin

package main

type KeyStore interface {
	List() ([]*SEKey, error)
	Generate(label string, requireTouch bool, useSE bool) (*SEKey, error)
	Delete(label string) error
	DeleteAll() error
}

type RealKeyStore struct{}

func (s *RealKeyStore) List() ([]*SEKey, error)                                        { return ListSEKeys() }
func (s *RealKeyStore) Generate(label string, requireTouch bool, useSE bool) (*SEKey, error) {
	return GenerateSEKey(label, requireTouch, useSE)
}
func (s *RealKeyStore) Delete(label string) error { return DeleteSEKey(label) }
func (s *RealKeyStore) DeleteAll() error           { return DeleteAllSEKeys() }
