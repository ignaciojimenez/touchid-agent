//go:build darwin

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestMakeTag(t *testing.T) {
	got := makeTag("mykey", true)
	want := "touchid-agent:t:mykey"
	if got != want {
		t.Errorf("makeTag(mykey, true) = %q, want %q", got, want)
	}
}

func TestMakeTag_NoTouch(t *testing.T) {
	got := makeTag("mykey", false)
	want := "touchid-agent:n:mykey"
	if got != want {
		t.Errorf("makeTag(mykey, false) = %q, want %q", got, want)
	}
}

func TestParseTag_Valid(t *testing.T) {
	tests := []struct {
		tag          string
		wantLabel    string
		wantTouch    bool
	}{
		{"touchid-agent:t:ssh", "ssh", true},
		{"touchid-agent:n:git", "git", false},
		{"touchid-agent:t:my-key-name", "my-key-name", true},
		{"touchid-agent:n:key_with_underscore", "key_with_underscore", false},
	}
	for _, tt := range tests {
		label, touch, ok := parseTag(tt.tag)
		if !ok {
			t.Errorf("parseTag(%q) returned ok=false", tt.tag)
			continue
		}
		if label != tt.wantLabel {
			t.Errorf("parseTag(%q) label = %q, want %q", tt.tag, label, tt.wantLabel)
		}
		if touch != tt.wantTouch {
			t.Errorf("parseTag(%q) touch = %v, want %v", tt.tag, touch, tt.wantTouch)
		}
	}
}

func TestParseTag_RoundTrip(t *testing.T) {
	for _, touch := range []bool{true, false} {
		tag := makeTag("testlabel", touch)
		label, gotTouch, ok := parseTag(tag)
		if !ok {
			t.Fatalf("parseTag(makeTag(testlabel, %v)) returned ok=false", touch)
		}
		if label != "testlabel" {
			t.Errorf("round-trip label = %q, want %q", label, "testlabel")
		}
		if gotTouch != touch {
			t.Errorf("round-trip touch = %v, want %v", gotTouch, touch)
		}
	}
}

func TestParseTag_InvalidPrefix(t *testing.T) {
	_, _, ok := parseTag("wrong-prefix:t:label")
	if ok {
		t.Error("parseTag with invalid prefix should return ok=false")
	}
}

func TestParseTag_MissingPolicy(t *testing.T) {
	_, _, ok := parseTag("touchid-agent:")
	if ok {
		t.Error("parseTag with missing policy should return ok=false")
	}
}

func TestParseTag_EmptyLabel(t *testing.T) {
	// parseTag is a low-level parser; label validation is handled by validateLabel.
	label, touch, ok := parseTag("touchid-agent:t:")
	if !ok {
		t.Fatal("parseTag should accept empty label at the parse level")
	}
	if label != "" {
		t.Errorf("expected empty label, got %q", label)
	}
	if !touch {
		t.Error("expected touch=true")
	}
}

func TestParseTag_NoColonSeparator(t *testing.T) {
	_, _, ok := parseTag("touchid-agent:tonly")
	if ok {
		t.Error("parseTag without second colon should return ok=false")
	}
}

func TestParseTag_EmptyString(t *testing.T) {
	_, _, ok := parseTag("")
	if ok {
		t.Error("parseTag with empty string should return ok=false")
	}
}

func TestParseTag_UnknownPolicy(t *testing.T) {
	label, touch, ok := parseTag("touchid-agent:x:mykey")
	if !ok {
		t.Fatal("parseTag with unknown policy should still parse")
	}
	if label != "mykey" {
		t.Errorf("label = %q, want %q", label, "mykey")
	}
	if touch {
		t.Error("unknown policy should not be treated as touch-required")
	}
}

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
