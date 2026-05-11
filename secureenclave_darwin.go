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

type Key struct {
	Label        string
	RequireTouch bool
	publicKey    *ecdsa.PublicKey
	keyData      []byte
	signFn       func(label string, digest []byte) ([]byte, error)
}

var publicKeyFromKeyData = sePublicKey

func (k *Key) Public() crypto.PublicKey { return k.publicKey }

func (k *Key) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if k.signFn != nil {
		return k.signFn(k.Label, digest)
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes (SHA-256), got %d", len(digest))
	}
	if len(k.keyData) == 0 {
		return nil, errors.New("key has no associated blob")
	}
	return seSign(k.keyData, digest)
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

func sePublicKey(keyData []byte) (*ecdsa.PublicKey, error) {
	if len(keyData) == 0 {
		return nil, errors.New("key data is empty")
	}

	var (
		pubOut *C.uint8_t
		pubLen C.size_t
		errStr *C.char
	)
	rc := C.se_public_key(
		(*C.uint8_t)(unsafe.Pointer(&keyData[0])), C.size_t(len(keyData)),
		&pubOut, &pubLen, &errStr,
	)
	if rc != 0 {
		msg := "unknown Secure Enclave error"
		if errStr != nil {
			msg = C.GoString(errStr)
			C.free(unsafe.Pointer(errStr))
		}
		return nil, errors.New(msg)
	}
	defer C.free(unsafe.Pointer(pubOut))

	pubRaw := C.GoBytes(unsafe.Pointer(pubOut), C.int(pubLen))
	pub, err := parseECPublicKey(pubRaw)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pub, nil
}

func parseECPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
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
	out := make([]byte, 65)
	out[0] = 0x04
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	copy(out[1+(32-len(xb)):33], xb)
	copy(out[33+(32-len(yb)):65], yb)
	return out
}
