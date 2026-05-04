//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestValidateLabel_Valid(t *testing.T) {
	valid := []string{"ssh", "git", "my-key", "key_1", "a"}
	for _, label := range valid {
		if err := validateLabel(label); err != nil {
			t.Errorf("validateLabel(%q) = %v, want nil", label, err)
		}
	}
}

func TestValidateLabel_Empty(t *testing.T) {
	err := validateLabel("")
	if err == nil {
		t.Error("validateLabel(\"\") should return error")
	}
}

func TestValidateLabel_WithColon(t *testing.T) {
	err := validateLabel("my:key")
	if err == nil {
		t.Error("validateLabel with colon should return error")
	}
}

func TestValidateLabel_WithSlash(t *testing.T) {
	err := validateLabel("my/key")
	if err == nil {
		t.Error("validateLabel with slash should return error")
	}
}

func TestValidateLabel_WithBackslash(t *testing.T) {
	err := validateLabel("my\\key")
	if err == nil {
		t.Error("validateLabel with backslash should return error")
	}
}

func TestValidateLabel_TooLong(t *testing.T) {
	long := strings.Repeat("a", 65)
	err := validateLabel(long)
	if err == nil {
		t.Error("validateLabel with >64 chars should return error")
	}
}

func TestValidateLabel_MaxLength(t *testing.T) {
	exact := strings.Repeat("a", 64)
	if err := validateLabel(exact); err != nil {
		t.Errorf("validateLabel with exactly 64 chars should succeed: %v", err)
	}
}

func TestValidateLabel_SpecialChars(t *testing.T) {
	valid := []string{"key-with-dashes", "key_with_underscores", "Key123", "KEY"}
	for _, label := range valid {
		if err := validateLabel(label); err != nil {
			t.Errorf("validateLabel(%q) = %v, want nil", label, err)
		}
	}
}

func TestValidateCreateFlags(t *testing.T) {
	cases := []struct {
		name     string
		software bool
		noTouch  bool
		wantErr  bool
	}{
		{"SE with Touch (default)", false, false, false},
		{"SE without Touch", false, true, false},
		{"software without Touch", true, true, false},
		{"software with Touch (rejected)", true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCreateFlags(tc.software, tc.noTouch)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "-no-touch") {
				t.Errorf("error should mention -no-touch, got: %v", err)
			}
		})
	}
}
