//go:build darwin

package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lsecureenclave
#cgo LDFLAGS: -framework CryptoKit -framework LocalAuthentication
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework Foundation
#include "secureenclave_bridge.h"
#include <stdlib.h>
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unsafe"
)

type SEKey struct {
	Label        string
	RequireTouch bool
	publicKey    *ecdsa.PublicKey
	keyData      []byte
	signFn       func(tag string, digest []byte) ([]byte, error)
}

func (k *SEKey) Public() crypto.PublicKey { return k.publicKey }

func (k *SEKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if k.signFn != nil {
		return k.signFn(k.Label, digest)
	}
	return nil, errors.New("sign: not implemented in Phase 1 spike")
}

func GenerateSEKey(label string, requireTouch bool, useSE bool) (*SEKey, error) {
	touchFlag := C.int(0)
	if requireTouch {
		touchFlag = C.int(1)
	}

	var (
		keyDataOut *C.uint8_t
		keyDataLen C.size_t
		pubOut     *C.uint8_t
		pubLen     C.size_t
		errStr     *C.char
	)

	rc := C.se_generate(touchFlag, &keyDataOut, &keyDataLen, &pubOut, &pubLen, &errStr)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return nil, fmt.Errorf("generate key: %s", msg)
	}
	defer C.free(unsafe.Pointer(keyDataOut))
	defer C.free(unsafe.Pointer(pubOut))

	keyData := C.GoBytes(unsafe.Pointer(keyDataOut), C.int(keyDataLen))
	pubRaw := C.GoBytes(unsafe.Pointer(pubOut), C.int(pubLen))

	pub, err := parseECPublicKey(pubRaw)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	return &SEKey{
		Label:        label,
		RequireTouch: requireTouch,
		publicKey:    pub,
		keyData:      keyData,
	}, nil
}

func parseECPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	// Uncompressed EC point: 0x04 || x (32 bytes) || y (32 bytes)
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("unexpected public key format (len=%d)", len(raw))
	}
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// Phase 1 stubs: persistence and listing arrive in Phase 3.

func ListSEKeys() ([]*SEKey, error) {
	return nil, nil
}

func DeleteSEKey(label string) error {
	return errors.New("delete: not implemented in Phase 1 spike")
}

func DeleteAllSEKeys() error {
	return errors.New("delete-all: not implemented in Phase 1 spike")
}

func classifyKeychainError(label string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("signing key %q: %w", label, err)
}
