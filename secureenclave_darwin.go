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

type Backend int

const (
	BackendSecureEnclave Backend = iota
	BackendSoftware
)

func (b Backend) String() string {
	switch b {
	case BackendSecureEnclave:
		return "secure-enclave"
	case BackendSoftware:
		return "software"
	default:
		return fmt.Sprintf("backend(%d)", int(b))
	}
}

func parseBackend(s string) (Backend, error) {
	switch s {
	case "secure-enclave":
		return BackendSecureEnclave, nil
	case "software":
		return BackendSoftware, nil
	default:
		return 0, fmt.Errorf("unknown backend %q", s)
	}
}

type SEKey struct {
	Label        string
	Backend      Backend
	RequireTouch bool
	publicKey    *ecdsa.PublicKey
	keyData      []byte
	signFn       func(label string, digest []byte) ([]byte, error)
}

func (k *SEKey) Public() crypto.PublicKey { return k.publicKey }

func (k *SEKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if k.signFn != nil {
		return k.signFn(k.Label, digest)
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes (SHA-256), got %d", len(digest))
	}
	if len(k.keyData) == 0 {
		return nil, errors.New("key has no associated blob")
	}
	switch k.Backend {
	case BackendSecureEnclave:
		return seSign(k.keyData, digest)
	case BackendSoftware:
		return swSign(k.keyData, digest)
	default:
		return nil, fmt.Errorf("unknown backend %d", k.Backend)
	}
}

func seSign(keyData, digest []byte) ([]byte, error) {
	var (
		sigOut *C.uint8_t
		sigLen C.size_t
		errStr *C.char
	)
	rc := C.se_sign(
		(*C.uint8_t)(unsafe.Pointer(&keyData[0])), C.size_t(len(keyData)),
		(*C.uint8_t)(unsafe.Pointer(&digest[0])), C.size_t(len(digest)),
		&sigOut, &sigLen, &errStr,
	)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return nil, errors.New(msg)
	}
	defer C.free(unsafe.Pointer(sigOut))
	return C.GoBytes(unsafe.Pointer(sigOut), C.int(sigLen)), nil
}

func swSign(keyData, digest []byte) ([]byte, error) {
	var (
		sigOut *C.uint8_t
		sigLen C.size_t
		errStr *C.char
	)
	rc := C.sw_sign(
		(*C.uint8_t)(unsafe.Pointer(&keyData[0])), C.size_t(len(keyData)),
		(*C.uint8_t)(unsafe.Pointer(&digest[0])), C.size_t(len(digest)),
		&sigOut, &sigLen, &errStr,
	)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return nil, errors.New(msg)
	}
	defer C.free(unsafe.Pointer(sigOut))
	return C.GoBytes(unsafe.Pointer(sigOut), C.int(sigLen)), nil
}

// generateSoftwareKey returns a fresh CryptoKit P-256 software key. The
// returned blob is the 32-byte raw private scalar (rawRepresentation).
func generateSoftwareKey() (keyData []byte, pub *ecdsa.PublicKey, err error) {
	var (
		keyDataOut *C.uint8_t
		keyDataLen C.size_t
		pubOut     *C.uint8_t
		pubLen     C.size_t
		errStr     *C.char
	)
	rc := C.sw_generate(&keyDataOut, &keyDataLen, &pubOut, &pubLen, &errStr)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return nil, nil, fmt.Errorf("generate software key: %s", msg)
	}
	defer C.free(unsafe.Pointer(keyDataOut))
	defer C.free(unsafe.Pointer(pubOut))

	keyData = C.GoBytes(unsafe.Pointer(keyDataOut), C.int(keyDataLen))
	pubRaw := C.GoBytes(unsafe.Pointer(pubOut), C.int(pubLen))

	pub, err = parseECPublicKey(pubRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}
	return keyData, pub, nil
}

// generateSEKey is the cgo entry point used by the keystore. It returns the
// raw SEP blob and parsed public key; persistence is the caller's job.
func generateSEKey(requireTouch bool) (keyData []byte, pub *ecdsa.PublicKey, err error) {
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
		return nil, nil, fmt.Errorf("generate key: %s", msg)
	}
	defer C.free(unsafe.Pointer(keyDataOut))
	defer C.free(unsafe.Pointer(pubOut))

	keyData = C.GoBytes(unsafe.Pointer(keyDataOut), C.int(keyDataLen))
	pubRaw := C.GoBytes(unsafe.Pointer(pubOut), C.int(pubLen))

	pub, err = parseECPublicKey(pubRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}
	return keyData, pub, nil
}

func keychainStore(label string, keyData []byte) error {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	var errStr *C.char
	rc := C.sw_keychain_store(
		cLabel,
		(*C.uint8_t)(unsafe.Pointer(&keyData[0])), C.size_t(len(keyData)),
		&errStr,
	)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return errors.New(msg)
	}
	return nil
}

func keychainLoad(label string) ([]byte, error) {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	var (
		dataOut *C.uint8_t
		dataLen C.size_t
		errStr  *C.char
	)
	rc := C.sw_keychain_load(
		cLabel,
		&dataOut, &dataLen,
		&errStr,
	)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return nil, errors.New(msg)
	}
	defer C.free(unsafe.Pointer(dataOut))
	return C.GoBytes(unsafe.Pointer(dataOut), C.int(dataLen)), nil
}

func keychainDelete(label string) error {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	var errStr *C.char
	rc := C.sw_keychain_delete(cLabel, &errStr)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return errors.New(msg)
	}
	return nil
}

func parseECPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	// Uncompressed EC point: 0x04 || x (32 bytes) || y (32 bytes)
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("unexpected public key format (len=%d)", len(raw))
	}
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key is not on the P-256 curve")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

func marshalECPublicKey(pub *ecdsa.PublicKey) []byte {
	// Uncompressed EC point: 0x04 || x (32 bytes) || y (32 bytes).
	out := make([]byte, 65)
	out[0] = 0x04
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	copy(out[1+(32-len(xb)):33], xb)
	copy(out[33+(32-len(yb)):65], yb)
	return out
}
