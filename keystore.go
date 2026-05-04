//go:build darwin

package main

type KeyStore interface {
	List() ([]*SEKey, error)
	Generate(label string, requireTouch bool, useSE bool) (*SEKey, error)
	Delete(label string) error
	DeleteAll() error
}
