//go:build darwin

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyKeychainError_Nil(t *testing.T) {
	if err := classifyKeychainError("test", nil); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestClassifyKeychainError_InteractionNotAllowed(t *testing.T) {
	err := classifyKeychainError("mykey", errors.New("User interaction is not allowed"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "screen locked") {
		t.Errorf("expected guidance about screen lock, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"mykey"`) {
		t.Errorf("expected key label in error, got: %v", err)
	}
}

func TestClassifyKeychainError_AuthFailed(t *testing.T) {
	err := classifyKeychainError("ssh", errors.New("Authentication failed"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Touch ID") {
		t.Errorf("expected Touch ID guidance, got: %v", err)
	}
}

func TestClassifyKeychainError_NotAvailable(t *testing.T) {
	err := classifyKeychainError("git", errors.New("resource not available"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "code-signed") {
		t.Errorf("expected code signing guidance, got: %v", err)
	}
}

func TestClassifyKeychainError_UserCanceled(t *testing.T) {
	err := classifyKeychainError("ssh", errors.New("User canceled the operation"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "canceled by the user") {
		t.Errorf("expected cancellation message, got: %v", err)
	}
}

func TestClassifyKeychainError_Unknown(t *testing.T) {
	orig := errors.New("something unexpected")
	err := classifyKeychainError("key1", orig)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, orig) {
		t.Error("wrapped error should preserve original")
	}
	if !strings.Contains(err.Error(), `"key1"`) {
		t.Errorf("expected key label in error, got: %v", err)
	}
}

func TestClassifyKeychainError_PreservesWrapping(t *testing.T) {
	orig := errors.New("Authentication failed for some reason")
	err := classifyKeychainError("ssh", orig)
	if !errors.Is(err, orig) {
		t.Error("classified error should wrap the original")
	}
}
