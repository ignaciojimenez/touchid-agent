//go:build darwin

package main

/*
#cgo LDFLAGS: -framework Security -framework Foundation -framework CoreFoundation
#include "secureenclave.h"
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
	"strings"
	"unsafe"
)

const tagPrefix = "touchid-agent:"

func classifyKeychainError(label string, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()

	switch {
	case strings.Contains(msg, "User interaction is not allowed"):
		return fmt.Errorf("signing key %q failed: Keychain requires user interaction but none is possible. "+
			"Is the screen locked or is the agent running in a non-interactive context? (%w)", label, err)
	case strings.Contains(msg, "Authentication failed"):
		return fmt.Errorf("signing key %q failed: Keychain authentication failed. "+
			"Touch ID may have been denied or the Keychain is locked. (%w)", label, err)
	case strings.Contains(msg, "not available"):
		return fmt.Errorf("signing key %q failed: the requested security resource is not available. "+
			"The binary may need to be code-signed with a Developer ID. (%w)", label, err)
	case strings.Contains(msg, "User canceled"):
		return fmt.Errorf("signing key %q: Touch ID prompt was canceled by the user. (%w)", label, err)
	default:
		return fmt.Errorf("signing key %q failed: %w", label, err)
	}
}

type SEKey struct {
	Label        string
	Tag          string
	RequireTouch bool
	publicKey    *ecdsa.PublicKey
	signFn       func(tag string, digest []byte) ([]byte, error)
}

func (k *SEKey) Public() crypto.PublicKey {
	return k.publicKey
}

func (k *SEKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if k.signFn != nil {
		return k.signFn(k.Tag, digest)
	}
	return seSign(k.Tag, digest)
}

func makeTag(label string, requireTouch bool) string {
	policy := "n"
	if requireTouch {
		policy = "t"
	}
	return fmt.Sprintf("%s%s:%s", tagPrefix, policy, label)
}

func parseTag(tag string) (label string, requireTouch bool, ok bool) {
	if !strings.HasPrefix(tag, tagPrefix) {
		return "", false, false
	}
	rest := tag[len(tagPrefix):]
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return "", false, false
	}
	return parts[1], parts[0] == "t", true
}

func GenerateSEKey(label string, requireTouch bool, useSE bool) (*SEKey, error) {
	tag := makeTag(label, requireTouch)

	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	touchFlag := C.int(0)
	if requireTouch {
		touchFlag = C.int(1)
	}
	seFlag := C.int(0)
	if useSE {
		seFlag = C.int(1)
	}

	var errStr *C.char
	rc := C.se_generate_key(cLabel, cTag, touchFlag, seFlag, &errStr)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return nil, fmt.Errorf("generate key: %s", msg)
	}

	pub, err := getPublicKey(tag)
	if err != nil {
		return nil, fmt.Errorf("read public key after generation: %w", err)
	}

	return &SEKey{
		Label:        label,
		Tag:          tag,
		RequireTouch: requireTouch,
		publicKey:    pub,
	}, nil
}

func getPublicKey(tag string) (*ecdsa.PublicKey, error) {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	var pubOut *C.uint8_t
	var pubLen C.size_t
	var errStr *C.char

	rc := C.se_get_public_key(cTag, &pubOut, &pubLen, &errStr)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return nil, fmt.Errorf("get public key: %s", msg)
	}
	defer C.free(unsafe.Pointer(pubOut))

	raw := C.GoBytes(unsafe.Pointer(pubOut), C.int(pubLen))
	return parseECPublicKey(raw)
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

func seSign(tag string, digest []byte) ([]byte, error) {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	var sigOut *C.uint8_t
	var sigLen C.size_t
	var errStr *C.char

	rc := C.se_sign(cTag,
		(*C.uint8_t)(unsafe.Pointer(&digest[0])), C.size_t(len(digest)),
		&sigOut, &sigLen, &errStr)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return nil, errors.New(msg)
	}
	defer C.free(unsafe.Pointer(sigOut))

	return C.GoBytes(unsafe.Pointer(sigOut), C.int(sigLen)), nil
}

func ListSEKeys() ([]*SEKey, error) {
	cPrefix := C.CString(tagPrefix)
	defer C.free(unsafe.Pointer(cPrefix))

	var resultOut *C.char
	var errStr *C.char

	rc := C.se_list_keys(cPrefix, &resultOut, &errStr)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return nil, fmt.Errorf("list keys: %s", msg)
	}
	defer C.free(unsafe.Pointer(resultOut))

	result := C.GoString(resultOut)
	if result == "" {
		return nil, nil
	}

	var keys []*SEKey
	for _, line := range strings.Split(strings.TrimSpace(result), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		tag := parts[0]
		label, requireTouch, ok := parseTag(tag)
		if !ok {
			continue
		}

		pub, err := getPublicKey(tag)
		if err != nil {
			continue
		}

		keys = append(keys, &SEKey{
			Label:        label,
			Tag:          tag,
			RequireTouch: requireTouch,
			publicKey:    pub,
		})
	}

	return keys, nil
}

func DeleteSEKey(label string) error {
	// Touch policy is encoded in the tag, so a label may have either variant.
	for _, touch := range []bool{true, false} {
		tag := makeTag(label, touch)
		cTag := C.CString(tag)
		var errStr *C.char
		rc := C.se_delete_key(cTag, &errStr)
		C.free(unsafe.Pointer(cTag))
		if rc != 0 {
			msg := C.GoString(errStr)
			C.free(unsafe.Pointer(errStr))
			return fmt.Errorf("delete key: %s", msg)
		}
	}
	return nil
}

func DeleteAllSEKeys() error {
	cPrefix := C.CString(tagPrefix)
	defer C.free(unsafe.Pointer(cPrefix))

	var errStr *C.char
	rc := C.se_delete_all_keys(cPrefix, &errStr)
	if rc != 0 {
		msg := C.GoString(errStr)
		C.free(unsafe.Pointer(errStr))
		return fmt.Errorf("delete all keys: %s", msg)
	}
	return nil
}
