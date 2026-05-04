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

	raw := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)

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
	// Valid length and prefix but the point (1, 1) is not on P-256.
	raw := make([]byte, 65)
	raw[0] = 0x04
	raw[32] = 1 // x = 1
	raw[64] = 1 // y = 1
	_, err := parseECPublicKey(raw)
	if err == nil {
		t.Error("should reject off-curve point")
	}
}

func TestBackend_StringRoundTrip(t *testing.T) {
	cases := []Backend{BackendSecureEnclave, BackendSoftware}
	for _, b := range cases {
		got, err := parseBackend(b.String())
		if err != nil {
			t.Errorf("parseBackend(%q) error: %v", b.String(), err)
		}
		if got != b {
			t.Errorf("parseBackend(%q) = %v, want %v", b.String(), got, b)
		}
	}
}

func TestBackend_ParseUnknown(t *testing.T) {
	if _, err := parseBackend("hsm-yolo"); err == nil {
		t.Error("parseBackend should reject unknown backend strings")
	}
}
