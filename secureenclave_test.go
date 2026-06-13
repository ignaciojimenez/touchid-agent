//go:build darwin

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestParseECPublicKey_Valid(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	raw := marshalECPublicKey(&priv.PublicKey)

	pub, err := parseECPublicKey(raw)
	if err != nil {
		t.Fatalf("parseECPublicKey failed: %v", err)
	}
	if pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("parsed public key does not match original")
	}
	if pub.Curve != elliptic.P256() {
		t.Error("parsed key should use P-256 curve")
	}
}

func TestParseECPublicKey_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := marshalECPublicKey(&priv.PublicKey)
	pub, err := parseECPublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("marshal/parse round-trip lost coordinates")
	}
}

func TestParseECPublicKey_WrongLength(t *testing.T) {
	_, err := parseECPublicKey(make([]byte, 33))
	if err == nil {
		t.Error("should reject 33-byte input")
	}
}

func TestParseECPublicKey_WrongPrefix(t *testing.T) {
	raw := make([]byte, 65)
	raw[0] = 0x02
	_, err := parseECPublicKey(raw)
	if err == nil {
		t.Error("should reject input without 0x04 prefix")
	}
}

func TestParseECPublicKey_ZeroBytes(t *testing.T) {
	_, err := parseECPublicKey(nil)
	if err == nil {
		t.Error("should reject nil input")
	}
}

func TestParseECPublicKey_Empty(t *testing.T) {
	_, err := parseECPublicKey([]byte{})
	if err == nil {
		t.Error("should reject empty input")
	}
}

func TestParseECPublicKey_CompressedPoint(t *testing.T) {
	compressed := make([]byte, 33)
	compressed[0] = 0x02
	_, err := parseECPublicKey(compressed)
	if err == nil {
		t.Error("should reject compressed EC point")
	}
}

func TestParseECPublicKey_OffCurve(t *testing.T) {
	raw := make([]byte, 65)
	raw[0] = 0x04
	raw[32] = 1
	raw[64] = 1
	_, err := parseECPublicKey(raw)
	if err == nil {
		t.Error("should reject off-curve point")
	}
}

func TestSEPublicKeyRejectsEmptyKeyData(t *testing.T) {
	_, err := sePublicKey(nil)
	if err == nil {
		t.Fatal("expected error for empty key data")
	}
}
