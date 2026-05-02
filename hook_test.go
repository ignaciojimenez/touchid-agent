//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPostHook_EmptyCommand(t *testing.T) {
	err := runPostHook("", HookEnv{Label: "test"})
	if err != nil {
		t.Errorf("empty hook should be no-op, got: %v", err)
	}
}

func TestRunPostHook_SetsEnvironment(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hook.sh")
	output := filepath.Join(dir, "env.txt")

	content := "#!/bin/bash\n" +
		"echo \"LABEL=$TOUCHID_AGENT_LABEL\" > " + output + "\n" +
		"echo \"PUBKEY=$TOUCHID_AGENT_PUBKEY\" >> " + output + "\n" +
		"echo \"FILE=$TOUCHID_AGENT_PUBKEY_FILE\" >> " + output + "\n" +
		"echo \"TOUCH=$TOUCHID_AGENT_TOUCH_REQUIRED\" >> " + output + "\n"

	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	env := HookEnv{
		Label:         "my-key",
		PubKey:        "fake-key-type PLACEHOLDER touchid-agent:my-key",
		PubKeyFile:    "/home/user/.ssh/touchid-agent-my-key.pub",
		TouchRequired: true,
	}

	if err := runPostHook(script, env); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)

	checks := []struct {
		label, want string
	}{
		{"LABEL", "LABEL=my-key"},
		{"PUBKEY", "PUBKEY=fake-key-type PLACEHOLDER touchid-agent:my-key"},
		{"FILE", "FILE=/home/user/.ssh/touchid-agent-my-key.pub"},
		{"TOUCH", "TOUCH=true"},
	}
	for _, c := range checks {
		if !strings.Contains(got, c.want) {
			t.Errorf("expected %s in output, got:\n%s", c.want, got)
		}
	}
}

func TestRunPostHook_TouchRequiredFalse(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hook.sh")
	output := filepath.Join(dir, "env.txt")

	content := "#!/bin/bash\necho $TOUCHID_AGENT_TOUCH_REQUIRED > " + output + "\n"
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	env := HookEnv{Label: "git", TouchRequired: false}
	if err := runPostHook(script, env); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != "false" {
		t.Errorf("TOUCHID_AGENT_TOUCH_REQUIRED = %q, want \"false\"", got)
	}
}

func TestRunPostHook_NonZeroExit(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hook.sh")

	if err := os.WriteFile(script, []byte("#!/bin/bash\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}

	err := runPostHook(script, HookEnv{Label: "test"})
	if err == nil {
		t.Error("expected error from failing hook")
	}
	if !strings.Contains(err.Error(), "post-create hook failed") {
		t.Errorf("error should mention hook failure, got: %v", err)
	}
}

func TestRunPostHook_NotFound(t *testing.T) {
	err := runPostHook("/nonexistent/hook.sh", HookEnv{Label: "test"})
	if err == nil {
		t.Error("expected error for missing hook")
	}
}

func TestRunPostHook_NotExecutable(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hook.sh")

	if err := os.WriteFile(script, []byte("#!/bin/bash\necho ok\n"), 0644); err != nil {
		t.Fatal(err)
	}

	err := runPostHook(script, HookEnv{Label: "test"})
	if err == nil {
		t.Error("expected error for non-executable hook")
	}
}

func TestBoolStr(t *testing.T) {
	if boolStr(true) != "true" {
		t.Error("boolStr(true) should return \"true\"")
	}
	if boolStr(false) != "false" {
		t.Error("boolStr(false) should return \"false\"")
	}
}
