//go:build darwin

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPostHook_EmptyCommand(t *testing.T) {
	err := runPostHook("", "test", "", "", true)
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

	err := runPostHook(script,
		"my-key",
		"fake-key-type PLACEHOLDER",
		"/home/user/.ssh/touchid-agent-my-key.pub",
		true,
	)
	if err != nil {
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

	err := runPostHook(script, "git", "", "", false)
	if err != nil {
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

	err := runPostHook(script, "test", "", "", true)
	if err == nil {
		t.Error("expected error from failing hook")
	}
	if !strings.Contains(err.Error(), "post-create hook failed") {
		t.Errorf("error should mention hook failure, got: %v", err)
	}
}

func TestRunPostHook_NotFound(t *testing.T) {
	err := runPostHook("/nonexistent/hook.sh", "test", "", "", true)
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

	err := runPostHook(script, "test", "", "", true)
	if err == nil {
		t.Error("expected error for non-executable hook")
	}
}

func TestRunPostHook_InheritsParentEnv(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hook.sh")
	output := filepath.Join(dir, "env.txt")

	content := "#!/bin/bash\necho \"PATH=$PATH\" > " + output + "\necho \"HOME=$HOME\" >> " + output + "\n"
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	err := runPostHook(script, "test", "", "", true)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)

	if !strings.Contains(got, "PATH=/") {
		t.Errorf("hook should inherit PATH from parent, got:\n%s", got)
	}
	if !strings.Contains(got, "HOME=/") {
		t.Errorf("hook should inherit HOME from parent, got:\n%s", got)
	}
}

func TestRunPostHook_SpacesInPubkeyFilePath(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hook.sh")
	output := filepath.Join(dir, "env.txt")

	pathWithSpaces := "/Users/test user/Library/my keys/touchid-agent-ssh.pub"

	content := "#!/bin/bash\necho \"$TOUCHID_AGENT_PUBKEY_FILE\" > " + output + "\n"
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	err := runPostHook(script, "ssh", "ecdsa-sha2-nistp256 AAAA", pathWithSpaces, true)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != pathWithSpaces {
		t.Errorf("PUBKEY_FILE = %q, want %q", got, pathWithSpaces)
	}
}

func TestRunPostHook_SpecialCharsInLabel(t *testing.T) {
	labels := []string{"my-key", "key.2", "key_name", "KEY-123"}
	for _, label := range labels {
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "hook.sh")
			output := filepath.Join(dir, "env.txt")

			content := "#!/bin/bash\necho \"$TOUCHID_AGENT_LABEL\" > " + output + "\n"
			if err := os.WriteFile(script, []byte(content), 0755); err != nil {
				t.Fatal(err)
			}

			err := runPostHook(script, label, "fake-pubkey", "/tmp/key.pub", true)
			if err != nil {
				t.Fatalf("hook failed for label %q: %v", label, err)
			}

			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(string(data)); got != label {
				t.Errorf("LABEL = %q, want %q", got, label)
			}
		})
	}
}

func TestRunPostHook_StdoutStderr(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hook.sh")

	content := "#!/bin/bash\necho 'hook-stdout-marker'\necho 'hook-stderr-marker' >&2\n"
	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	origStdout := os.Stdout
	origStderr := os.Stderr
	defer func() {
		os.Stdout = origStdout
		os.Stderr = origStderr
	}()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	os.Stdout = outW
	os.Stderr = errW

	hookErr := runPostHook(script, "test", "", "", true)

	outW.Close()
	errW.Close()

	if hookErr != nil {
		t.Fatal(hookErr)
	}

	var outBuf, errBuf bytes.Buffer
	outBuf.ReadFrom(outR)
	errBuf.ReadFrom(errR)

	if !strings.Contains(outBuf.String(), "hook-stdout-marker") {
		t.Errorf("hook stdout not captured, got: %q", outBuf.String())
	}
	if !strings.Contains(errBuf.String(), "hook-stderr-marker") {
		t.Errorf("hook stderr not captured, got: %q", errBuf.String())
	}
}

func TestRunPostHook_ArgumentsInCommandRejected(t *testing.T) {
	err := runPostHook("/bin/echo hello", "test", "", "", true)
	if err == nil {
		t.Error("exec.Command treats the whole string as the binary name; should fail")
	}
}

func TestContribHook_GithubUpload(t *testing.T) {
	dir := t.TempDir()
	mockBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(mockBin, 0755); err != nil {
		t.Fatal(err)
	}

	ghLog := filepath.Join(dir, "gh-calls.txt")
	mockGh := "#!/bin/bash\necho \"$@\" >> " + ghLog + "\n"
	if err := os.WriteFile(filepath.Join(mockBin, "gh"), []byte(mockGh), 0755); err != nil {
		t.Fatal(err)
	}

	pubFile := filepath.Join(dir, "touchid-agent-ssh.pub")
	if err := os.WriteFile(pubFile, []byte("ecdsa-sha2-nistp256 AAAA touchid-agent:ssh\n"), 0644); err != nil {
		t.Fatal(err)
	}

	hookPath, err := filepath.Abs("contrib/hooks/github-upload.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hookPath); err != nil {
		t.Skipf("shipped hook not found: %v", err)
	}

	cmd := hookScript(t, hookPath, map[string]string{
		"PATH":                      mockBin + ":" + os.Getenv("PATH"),
		"TOUCHID_AGENT_LABEL":       "ssh",
		"TOUCHID_AGENT_PUBKEY":      "fake-key-type PLACEHOLDER touchid-agent:ssh",
		"TOUCHID_AGENT_PUBKEY_FILE": pubFile,
		"TOUCHID_AGENT_TOUCH_REQUIRED": "true",
	})

	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		t.Fatalf("github-upload.sh failed: %v\noutput: %s", runErr, out)
	}

	data, err := os.ReadFile(ghLog)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)

	if !strings.Contains(got, "ssh-key add") {
		t.Errorf("expected gh ssh-key add call, got:\n%s", got)
	}
	if !strings.Contains(got, "--type authentication") {
		t.Errorf("expected --type authentication, got:\n%s", got)
	}
	if !strings.Contains(got, "touchid-agent:ssh") {
		t.Errorf("expected title touchid-agent:ssh, got:\n%s", got)
	}
}

func TestContribHook_GithubSigning(t *testing.T) {
	dir := t.TempDir()
	mockBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(mockBin, 0755); err != nil {
		t.Fatal(err)
	}

	ghLog := filepath.Join(dir, "gh-calls.txt")
	gitLog := filepath.Join(dir, "git-calls.txt")

	mockGh := "#!/bin/bash\necho \"$@\" >> " + ghLog + "\n"
	if err := os.WriteFile(filepath.Join(mockBin, "gh"), []byte(mockGh), 0755); err != nil {
		t.Fatal(err)
	}

	mockGit := "#!/bin/bash\necho \"$@\" >> " + gitLog + "\n"
	if err := os.WriteFile(filepath.Join(mockBin, "git"), []byte(mockGit), 0755); err != nil {
		t.Fatal(err)
	}

	pubFile := filepath.Join(dir, "touchid-agent-git.pub")
	if err := os.WriteFile(pubFile, []byte("ecdsa-sha2-nistp256 AAAA touchid-agent:git\n"), 0644); err != nil {
		t.Fatal(err)
	}

	hookPath, err := filepath.Abs("contrib/hooks/github-signing.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hookPath); err != nil {
		t.Skipf("shipped hook not found: %v", err)
	}

	cmd := hookScript(t, hookPath, map[string]string{
		"PATH":                      mockBin + ":" + os.Getenv("PATH"),
		"TOUCHID_AGENT_LABEL":       "git",
		"TOUCHID_AGENT_PUBKEY":      "fake-key-type PLACEHOLDER touchid-agent:git",
		"TOUCHID_AGENT_PUBKEY_FILE": pubFile,
		"TOUCHID_AGENT_TOUCH_REQUIRED": "false",
	})

	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		t.Fatalf("github-signing.sh failed: %v\noutput: %s", runErr, out)
	}

	ghData, err := os.ReadFile(ghLog)
	if err != nil {
		t.Fatal(err)
	}
	ghGot := string(ghData)

	if !strings.Contains(ghGot, "ssh-key add") {
		t.Errorf("expected gh ssh-key add, got:\n%s", ghGot)
	}
	if !strings.Contains(ghGot, "--type signing") {
		t.Errorf("expected --type signing, got:\n%s", ghGot)
	}

	gitData, err := os.ReadFile(gitLog)
	if err != nil {
		t.Fatal(err)
	}
	gitGot := string(gitData)

	for _, want := range []string{"gpg.format ssh", "user.signingkey", "commit.gpgsign true"} {
		if !strings.Contains(gitGot, want) {
			t.Errorf("expected git config containing %q, got:\n%s", want, gitGot)
		}
	}
}

// hookScript builds an exec.Cmd that runs a hook script with a controlled environment.
func hookScript(t *testing.T, path string, env map[string]string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/bin/bash", path)
	cmd.Env = []string{}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd
}
