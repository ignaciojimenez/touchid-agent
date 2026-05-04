//go:build darwin

package main

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
)

func TestDebugf_Disabled(t *testing.T) {
	var buf bytes.Buffer
	old := debugLogger
	debugLogger = log.New(&buf, "", 0)
	defer func() { debugLogger = old }()

	debugLogger = log.New(io.Discard, "", 0)
	debugf("should not appear: %d", 42)

	if buf.Len() != 0 {
		t.Errorf("expected no output when debug disabled, got: %s", buf.String())
	}
}

func TestDebugf_Enabled(t *testing.T) {
	var buf bytes.Buffer
	old := debugLogger
	debugLogger = log.New(&buf, "debug: ", 0)
	defer func() { debugLogger = old }()

	debugf("test message: %d", 42)
	got := buf.String()
	if !strings.Contains(got, "debug: test message: 42") {
		t.Errorf("expected debug output, got: %s", got)
	}
}

func TestDebugf_AgentListLogs(t *testing.T) {
	var buf bytes.Buffer
	old := debugLogger
	debugLogger = log.New(&buf, "debug: ", 0)
	defer func() { debugLogger = old }()

	a, store := newTestAgent(t)
	store.Generate("dbg-test", false)

	_, err := a.List()
	if err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	if !strings.Contains(got, "List: returning 1 key(s)") {
		t.Errorf("expected List debug log, got: %s", got)
	}
}
