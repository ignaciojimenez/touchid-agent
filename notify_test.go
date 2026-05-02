//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestEscapeForAppleScript_Backslash(t *testing.T) {
	got := escapeForAppleScript(`hello\world`)
	if !strings.Contains(got, `\\`) {
		t.Errorf("backslash not escaped: %q", got)
	}
}

func TestEscapeForAppleScript_Quotes(t *testing.T) {
	got := escapeForAppleScript(`say "hello"`)
	if strings.Contains(got, `"hello"`) {
		t.Errorf("quotes not escaped: %q", got)
	}
	want := `say \"hello\"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEscapeForAppleScript_Empty(t *testing.T) {
	got := escapeForAppleScript("")
	if got != "" {
		t.Errorf("empty string should remain empty, got %q", got)
	}
}

func TestEscapeForAppleScript_Backticks(t *testing.T) {
	got := escapeForAppleScript("hello `whoami` world")
	if strings.Contains(got, "`") {
		t.Errorf("backticks should be stripped: %q", got)
	}
}

func TestEscapeForAppleScript_DollarParen(t *testing.T) {
	got := escapeForAppleScript("hello $(whoami) world")
	if strings.Contains(got, "$(") {
		t.Errorf("$() should be stripped: %q", got)
	}
}

func TestEscapeForAppleScript_Normal(t *testing.T) {
	input := "Waiting for Touch ID authentication..."
	got := escapeForAppleScript(input)
	if got != input {
		t.Errorf("normal message should be unchanged: got %q, want %q", got, input)
	}
}
