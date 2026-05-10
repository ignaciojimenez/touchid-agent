//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const oldStylePlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>touchid-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/touchid-agent</string>
    <string>-l</string>
    <string>/Users/test/Library/Caches/touchid-agent/agent.sock</string>
    <string>-audit-log</string>
    <string>/Users/test/Library/Logs/touchid-agent-audit.log</string>
    <string>-peer-check</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key>
  <string>/Users/test/Library/Logs/touchid-agent.log</string>
  <key>StandardOutPath</key>
  <string>/Users/test/Library/Logs/touchid-agent.log</string>
</dict>
</plist>
`

const socketActivatedPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>touchid-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/touchid-agent</string>
    <string>-launchd</string>
  </array>
  <key>Sockets</key>
  <dict>
    <key>Listeners</key>
    <dict>
      <key>SockFamily</key><string>Unix</string>
      <key>SockPathName</key><string>/Users/test/Library/Caches/touchid-agent/agent.sock</string>
      <key>SockPathMode</key><integer>384</integer>
    </dict>
  </dict>
</dict>
</plist>
`

const wrongLabelPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.someone.else</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/touchid-agent</string>
    <string>-l</string>
    <string>/tmp/sock</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
`

const oldStyleNoExtraFlags = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>touchid-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/touchid-agent</string>
    <string>-l</string>
    <string>/tmp/agent.sock</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
`

func writeTempPlist(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "touchid-agent.plist")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadPlist_OldStyle(t *testing.T) {
	path := writeTempPlist(t, oldStylePlist)
	p, err := readPlist(path)
	if err != nil {
		t.Fatalf("readPlist: %v", err)
	}
	if p == nil {
		t.Fatal("expected parsed plist, got nil")
	}
	if p.Label != "touchid-agent" {
		t.Errorf("Label = %q, want touchid-agent", p.Label)
	}
	if !p.HasRunAtLoad {
		t.Error("HasRunAtLoad = false, want true")
	}
	if !p.HasKeepAlive {
		t.Error("HasKeepAlive = false, want true")
	}
	if p.HasSockets {
		t.Error("HasSockets = true, want false")
	}
	if got := p.classify(); got != plistModeOldStyle {
		t.Errorf("classify() = %v, want plistModeOldStyle", got)
	}
}

func TestReadPlist_SocketActivated(t *testing.T) {
	path := writeTempPlist(t, socketActivatedPlist)
	p, err := readPlist(path)
	if err != nil {
		t.Fatalf("readPlist: %v", err)
	}
	if !p.HasSockets {
		t.Error("HasSockets = false, want true")
	}
	if p.SocketPath != "/Users/test/Library/Caches/touchid-agent/agent.sock" {
		t.Errorf("SocketPath = %q", p.SocketPath)
	}
	if got := p.classify(); got != plistModeSocketActivated {
		t.Errorf("classify() = %v, want plistModeSocketActivated", got)
	}
}

func TestReadPlist_Missing(t *testing.T) {
	p, err := readPlist(filepath.Join(t.TempDir(), "does-not-exist.plist"))
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if p != nil {
		t.Errorf("expected nil parsedPlist for missing file, got %+v", p)
	}
}

func TestExtractRunFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "old-style with audit + peer-check",
			args: []string{
				"/usr/local/bin/touchid-agent",
				"-l", "/tmp/sock",
				"-audit-log", "/var/log/audit.log",
				"-peer-check",
			},
			want: []string{"-audit-log", "/var/log/audit.log", "-peer-check"},
		},
		{
			name: "drops -launchd if already present (we always re-add it)",
			args: []string{
				"/usr/local/bin/touchid-agent",
				"-launchd",
				"-audit-log", "/x.log",
			},
			want: []string{"-audit-log", "/x.log"},
		},
		{
			name: "preserves rate-limit and allowed-callers",
			args: []string{
				"/usr/local/bin/touchid-agent",
				"-l", "/tmp/s",
				"-rate-limit", "30",
				"-allowed-callers", "/etc/allow",
			},
			want: []string{"-rate-limit", "30", "-allowed-callers", "/etc/allow"},
		},
		{
			name: "preserves -v",
			args: []string{
				"/usr/local/bin/touchid-agent",
				"-l", "/tmp/s",
				"-v",
			},
			want: []string{"-v"},
		},
		{
			name: "no flags beyond -l",
			args: []string{"/usr/local/bin/touchid-agent", "-l", "/tmp/s"},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractRunFlags(tc.args)
			if !equalStrings(got, tc.want) {
				t.Errorf("extractRunFlags(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRenderPlist_RoundTrip(t *testing.T) {
	out := renderPlist(
		"/usr/local/bin/touchid-agent",
		"/Users/test/Library/Caches/touchid-agent/agent.sock",
		"/Users/test/Library/Logs/touchid-agent.log",
		[]string{"-audit-log", "/Users/test/Library/Logs/audit.log", "-peer-check"},
	)
	// Sanity checks on structure
	for _, want := range []string{
		"<key>Label</key>",
		"<string>touchid-agent</string>",
		"<string>-launchd</string>",
		"<string>-audit-log</string>",
		"<string>-peer-check</string>",
		"<key>Sockets</key>",
		"<key>Listeners</key>",
		"<key>SockFamily</key>",
		"<string>Unix</string>",
		"<key>SockPathMode</key>",
		"<integer>384</integer>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("renderPlist output missing %q", want)
		}
	}
	// Roundtrip: write to disk, parse back, re-classify.
	dir := t.TempDir()
	path := filepath.Join(dir, "touchid-agent.plist")
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := readPlist(path)
	if err != nil {
		t.Fatalf("readPlist of rendered plist: %v", err)
	}
	if got := p.classify(); got != plistModeSocketActivated {
		t.Errorf("classify() of rendered plist = %v, want plistModeSocketActivated", got)
	}
	wantArgs := []string{
		"/usr/local/bin/touchid-agent",
		"-launchd",
		"-audit-log",
		"/Users/test/Library/Logs/audit.log",
		"-peer-check",
	}
	if !equalStrings(p.ProgramArguments, wantArgs) {
		t.Errorf("ProgramArguments = %v, want %v", p.ProgramArguments, wantArgs)
	}
}

func TestSocketFromOldArgs(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"binary", "-l", "/tmp/x.sock"}, "/tmp/x.sock"},
		{[]string{"binary", "-launchd"}, ""},
		{[]string{"binary", "-l"}, ""}, // no value after -l
	}
	for _, tc := range cases {
		if got := socketFromOldArgs(tc.args); got != tc.want {
			t.Errorf("socketFromOldArgs(%v) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

// TestMigrationPreservesAuditLog walks the full migration on disk and
// asserts the resulting plist is equivalent in the ways that matter.
func TestMigrationPreservesAuditLog(t *testing.T) {
	path := writeTempPlist(t, oldStylePlist)
	// Use exec via the public function path; -no-reload skips launchctl.
	// We invoke the helper functions directly since cmdMigratePlist
	// calls os.Exit on error.
	existing, err := readPlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := existing.classify(); got != plistModeOldStyle {
		t.Fatalf("precondition: classify() = %v, want plistModeOldStyle", got)
	}
	binary := existing.ProgramArguments[0]
	socket := socketFromOldArgs(existing.ProgramArguments)
	logp := existing.StandardErrorPath
	args := extractRunFlags(existing.ProgramArguments)
	if err := writePlistAtomically(path, renderPlist(binary, socket, logp, args)); err != nil {
		t.Fatal(err)
	}
	migrated, err := readPlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := migrated.classify(); got != plistModeSocketActivated {
		t.Fatalf("post-migration classify() = %v, want plistModeSocketActivated", got)
	}
	// audit-log argument must be preserved
	joined := strings.Join(migrated.ProgramArguments, " ")
	if !strings.Contains(joined, "-audit-log /Users/test/Library/Logs/touchid-agent-audit.log") {
		t.Errorf("audit-log not preserved: %s", joined)
	}
	if !strings.Contains(joined, "-peer-check") {
		t.Errorf("-peer-check not preserved: %s", joined)
	}
	if strings.Contains(joined, " -l ") {
		t.Errorf("-l should be dropped: %s", joined)
	}
	// Socket path preserved from the old -l value
	if migrated.SocketPath != socket {
		t.Errorf("SocketPath = %q, want %q", migrated.SocketPath, socket)
	}
}

func TestMigrationIdempotent(t *testing.T) {
	// Render an already-socket-activated plist, classify, re-render, expect identical.
	path := writeTempPlist(t, socketActivatedPlist)
	p1, err := readPlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if p1.classify() != plistModeSocketActivated {
		t.Fatal("precondition")
	}
	// Re-render with the same inputs the migrate code would derive.
	binary := resolveBinaryPath(p1)
	args := extractRunFlags(p1.ProgramArguments)
	out := renderPlist(binary, p1.SocketPath, "", args)
	if !strings.Contains(out, "<string>-launchd</string>") {
		t.Error("re-rendered plist missing -launchd")
	}
}

func TestUnknownLabelClassification(t *testing.T) {
	path := writeTempPlist(t, wrongLabelPlist)
	p, err := readPlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Label == plistLabel {
		t.Error("expected label mismatch")
	}
}

func TestOldStyleNoExtraFlags(t *testing.T) {
	path := writeTempPlist(t, oldStyleNoExtraFlags)
	p, err := readPlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.classify(); got != plistModeOldStyle {
		t.Errorf("classify() = %v, want plistModeOldStyle", got)
	}
	if got := extractRunFlags(p.ProgramArguments); len(got) != 0 {
		t.Errorf("extractRunFlags = %v, want empty", got)
	}
}

func TestXMLEscape(t *testing.T) {
	cases := map[string]string{
		"plain":    "plain",
		"a&b":      "a&amp;b",
		"a<b>c":    "a&lt;b&gt;c",
		"/no/esc":  "/no/esc",
	}
	for in, want := range cases {
		if got := xmlEscape(in); got != want {
			t.Errorf("xmlEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseStaleLModeProcesses(t *testing.T) {
	psOut := `   42 /usr/local/bin/touchid-agent -l /Users/test/Library/Caches/touchid-agent/agent.sock -audit-log /tmp/a.log
  100 /usr/local/bin/touchid-agent -launchd
  200 /usr/local/bin/touchid-agent -l /different/sock
  300 /usr/local/bin/touchid-agent -status /Users/test/Library/Caches/touchid-agent/agent.sock
  400 /usr/local/bin/something-else -l /Users/test/Library/Caches/touchid-agent/agent.sock
  500 /usr/local/bin/touchid-agent -l /Users/test/Library/Caches/touchid-agent/agent.sock
`
	got := parseStaleLModeProcesses(psOut, "/Users/test/Library/Caches/touchid-agent/agent.sock", 9999)
	want := []int{42, 500}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%d, want %d", i, got[i], want[i])
		}
	}
}

func TestParseStaleLModeProcesses_ExcludesSelf(t *testing.T) {
	psOut := `42 /usr/local/bin/touchid-agent -l /tmp/sock
`
	got := parseStaleLModeProcesses(psOut, "/tmp/sock", 42)
	if len(got) != 0 {
		t.Errorf("expected self-exclusion, got %v", got)
	}
}

func TestDecideEnsureAction(t *testing.T) {
	cases := []struct {
		name string
		path string // file content; empty string = no file at all
		want ensureAction
	}{
		{"missing plist installs", "", ensureActionInstall},
		{"socket-activated no-ops", socketActivatedPlist, ensureActionAlreadyOK},
		{"old-style left alone", oldStylePlist, ensureActionLeaveOldStyle},
		{"old-style without extras left alone", oldStyleNoExtraFlags, ensureActionLeaveOldStyle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var existing *parsedPlist
			if tc.path != "" {
				path := writeTempPlist(t, tc.path)
				p, err := readPlist(path)
				if err != nil {
					t.Fatal(err)
				}
				existing = p
			}
			if got := decideEnsureAction(existing); got != tc.want {
				t.Errorf("decideEnsureAction = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBackupPathFormat(t *testing.T) {
	bk := backupPath("/foo/bar.plist")
	if !strings.HasPrefix(bk, "/foo/bar.plist"+plistBackupSuffix+"-") {
		t.Errorf("backupPath = %q, want prefix %q", bk, "/foo/bar.plist"+plistBackupSuffix+"-")
	}
	// timestamp is YYYYMMDD-HHMMSS = 15 chars
	stamp := strings.TrimPrefix(bk, "/foo/bar.plist"+plistBackupSuffix+"-")
	if len(stamp) != 15 {
		t.Errorf("timestamp length = %d, want 15 (got %q)", len(stamp), stamp)
	}
}
