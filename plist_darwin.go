//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// plist_darwin.go implements -install-plist and -migrate-plist.
//
// Both commands write a socket-activated launchd plist to
// ~/Library/LaunchAgents/touchid-agent.plist and (re)load it via
// launchctl. -install-plist is for new installs; -migrate-plist
// rewrites an existing -l-mode plist while preserving extra flags
// (-audit-log, -peer-check, -rate-limit, -allowed-callers).

const (
	plistLabel        = "touchid-agent"
	plistRelPath      = "Library/LaunchAgents/touchid-agent.plist"
	socketRelPath     = "Library/Caches/touchid-agent/agent.sock"
	logRelPath        = "Library/Logs/touchid-agent.log"
	plistSocketsKey   = "Listeners" // must match launchdSocketName
	plistFileMode     = 0o644
	plistBackupSuffix = ".bak-pre-migrate"
)

// preservedAgentFlags lists the agent flags we carry across migration.
// Flags not in this set are dropped because they have no meaning under
// socket activation (-l) or are not agent flags.
var preservedAgentFlags = map[string]bool{
	"-audit-log":       true,
	"-peer-check":      true,
	"-rate-limit":      true,
	"-allowed-callers": true,
	"-v":               true,
}

// flagTakesValue marks flags whose next argv element is the value.
var flagTakesValue = map[string]bool{
	"-audit-log":       true,
	"-rate-limit":      true,
	"-allowed-callers": true,
	"-l":               true,
}

type plistMode int

const (
	plistModeUnknown plistMode = iota
	plistModeOldStyle
	plistModeSocketActivated
	plistModeMissing
)

func (m plistMode) String() string {
	switch m {
	case plistModeOldStyle:
		return "old-style (-l + RunAtLoad/KeepAlive)"
	case plistModeSocketActivated:
		return "socket-activated (-launchd)"
	case plistModeMissing:
		return "missing"
	default:
		return "unknown"
	}
}

// parsedPlist captures the fields we care about from an existing plist.
type parsedPlist struct {
	Label            string
	ProgramArguments []string
	HasSockets       bool
	SocketPath       string // SockPathName of the "Listeners" socket, if any
	HasRunAtLoad     bool
	HasKeepAlive     bool
	StandardOutPath  string
	StandardErrorPath string
}

// classify returns the plist mode based on its content.
func (p *parsedPlist) classify() plistMode {
	if p == nil {
		return plistModeMissing
	}
	hasL, hasLaunchd := false, false
	for _, a := range p.ProgramArguments {
		switch a {
		case "-l":
			hasL = true
		case "-launchd":
			hasLaunchd = true
		}
	}
	switch {
	case hasLaunchd && p.HasSockets:
		return plistModeSocketActivated
	case hasL && (p.HasRunAtLoad || p.HasKeepAlive):
		return plistModeOldStyle
	case hasL:
		// -l with no RunAtLoad/KeepAlive is unusual but still old-style
		return plistModeOldStyle
	default:
		return plistModeUnknown
	}
}

// readPlist parses a plist file via /usr/bin/plutil. Returns
// (nil, nil) if the file does not exist.
func readPlist(path string) (*parsedPlist, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("stat plist: %w", err)
	}
	out, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", path).Output()
	if err != nil {
		return nil, fmt.Errorf("plutil parse %s: %w", path, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("decode plist json: %w", err)
	}
	p := &parsedPlist{}
	if v, ok := raw["Label"].(string); ok {
		p.Label = v
	}
	if args, ok := raw["ProgramArguments"].([]any); ok {
		for _, a := range args {
			if s, ok := a.(string); ok {
				p.ProgramArguments = append(p.ProgramArguments, s)
			}
		}
	}
	if v, ok := raw["RunAtLoad"].(bool); ok {
		p.HasRunAtLoad = v
	}
	if v, ok := raw["KeepAlive"].(bool); ok {
		p.HasKeepAlive = v
	} else if _, ok := raw["KeepAlive"].(map[string]any); ok {
		p.HasKeepAlive = true
	}
	if s, ok := raw["StandardOutPath"].(string); ok {
		p.StandardOutPath = s
	}
	if s, ok := raw["StandardErrorPath"].(string); ok {
		p.StandardErrorPath = s
	}
	if sockets, ok := raw["Sockets"].(map[string]any); ok {
		p.HasSockets = true
		if listener, ok := sockets[plistSocketsKey].(map[string]any); ok {
			if path, ok := listener["SockPathName"].(string); ok {
				p.SocketPath = path
			}
		}
	}
	return p, nil
}

// extractRunFlags walks ProgramArguments (excluding the binary at [0])
// and returns the agent flags worth preserving in the new plist.
func extractRunFlags(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	var out []string
	i := 1 // skip binary path
	for i < len(args) {
		a := args[i]
		switch {
		case preservedAgentFlags[a] && flagTakesValue[a]:
			if i+1 < len(args) {
				out = append(out, a, args[i+1])
				i += 2
				continue
			}
			i++
		case preservedAgentFlags[a]:
			out = append(out, a)
			i++
		default:
			// unknown or non-preserved flag (e.g. -l, -launchd, value of -l)
			if flagTakesValue[a] {
				i += 2
			} else {
				i++
			}
		}
	}
	return out
}

// renderPlist returns a deterministic XML plist for socket activation.
// extraArgs go after "-launchd" in ProgramArguments.
func renderPlist(binaryPath, socketPath, logPath string, extraArgs []string) string {
	var argEntries strings.Builder
	argEntries.WriteString(fmt.Sprintf("    <string>%s</string>\n", xmlEscape(binaryPath)))
	argEntries.WriteString("    <string>-launchd</string>\n")
	for _, a := range extraArgs {
		argEntries.WriteString(fmt.Sprintf("    <string>%s</string>\n", xmlEscape(a)))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
%s  </array>
  <key>Sockets</key>
  <dict>
    <key>%s</key>
    <dict>
      <key>SockFamily</key>
      <string>Unix</string>
      <key>SockPathName</key>
      <string>%s</string>
      <key>SockPathMode</key>
      <integer>384</integer>
    </dict>
  </dict>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardErrorPath</key>
  <string>%s</string>
  <key>StandardOutPath</key>
  <string>%s</string>
</dict>
</plist>
`, plistLabel, argEntries.String(), plistSocketsKey, xmlEscape(socketPath), xmlEscape(logPath), xmlEscape(logPath))
}

// xmlEscape handles the small set of characters that can appear in
// filesystem paths.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// defaultPlistPath returns ~/Library/LaunchAgents/touchid-agent.plist.
func defaultPlistPath() string { return filepath.Join(os.Getenv("HOME"), plistRelPath) }

// defaultSocketPath returns ~/Library/Caches/touchid-agent/agent.sock.
func defaultSocketPath() string { return filepath.Join(os.Getenv("HOME"), socketRelPath) }

// defaultLogPath returns ~/Library/Logs/touchid-agent.log.
func defaultLogPath() string { return filepath.Join(os.Getenv("HOME"), logRelPath) }

// resolveBinaryPath returns the path to use for ProgramArguments[0].
// Prefers the existing plist's binary (so users on /opt/homebrew or
// elsewhere are preserved); falls back to the running binary.
func resolveBinaryPath(existing *parsedPlist) string {
	if existing != nil && len(existing.ProgramArguments) > 0 && existing.ProgramArguments[0] != "" {
		return existing.ProgramArguments[0]
	}
	if exe, err := os.Executable(); err == nil {
		// Resolve symlinks so we get the real binary path.
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			return real
		}
		return exe
	}
	return "/usr/local/bin/touchid-agent"
}

// writePlistAtomically writes content to path via temp+rename.
func writePlistAtomically(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		// best-effort cleanup if rename fails
		os.Remove(tmpName)
	}()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(plistFileMode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

// backupPath returns a unique backup filename for path.
func backupPath(path string) string {
	stamp := time.Now().UTC().Format("20060102-150405")
	return fmt.Sprintf("%s%s-%s", path, plistBackupSuffix, stamp)
}

// runLaunchctl executes launchctl <action> <arg> and returns its
// combined output for diagnostics. Errors from `unload` of an unloaded
// plist are returned to the caller to decide whether to ignore.
func runLaunchctl(action, arg string) ([]byte, error) {
	return exec.Command("/bin/launchctl", action, arg).CombinedOutput()
}

// reloadPlist runs `launchctl unload` (ignoring errors) then
// `launchctl load`, and verifies via cmdStatus-equivalent.
func reloadPlist(plistPath, socketPath string) error {
	// unload may fail if not loaded; that's fine.
	_, _ = runLaunchctl("unload", plistPath)
	if out, err := runLaunchctl("load", plistPath); err != nil {
		return fmt.Errorf("launchctl load %s: %w (%s)", plistPath, err, strings.TrimSpace(string(out)))
	}
	// Give launchd a moment to register the socket.
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("socket %s did not appear after load", socketPath)
}

// cmdInstallPlist writes a new socket-activation plist and loads it.
// Idempotent: no-op if an equivalent plist is already in place.
func cmdInstallPlist(plistPath, auditLogPath string, noReload bool) {
	if plistPath == "" {
		plistPath = defaultPlistPath()
	}
	existing, err := readPlist(plistPath)
	if err != nil {
		fatalf("Could not read existing plist %s: %v", plistPath, err)
	}
	mode := plistModeMissing
	if existing != nil {
		mode = existing.classify()
		if existing.Label != "" && existing.Label != plistLabel {
			fatalf("Existing plist at %s has Label=%q, refusing to overwrite (expected %q).",
				plistPath, existing.Label, plistLabel)
		}
	}
	switch mode {
	case plistModeSocketActivated:
		fmt.Printf("Plist already socket-activated at %s — nothing to do.\n", plistPath)
		fmt.Printf("Socket: %s\n", existing.SocketPath)
		return
	case plistModeOldStyle:
		fatalf("Existing plist at %s is old-style. Run `touchid-agent -migrate-plist` instead.", plistPath)
	case plistModeUnknown:
		if existing != nil {
			fatalf("Existing plist at %s does not match expected layout. Inspect manually or remove it before re-running.", plistPath)
		}
	}

	binary := resolveBinaryPath(existing)
	socketPath := defaultSocketPath()
	logPath := defaultLogPath()
	var extraArgs []string
	if auditLogPath != "" {
		extraArgs = append(extraArgs, "-audit-log", auditLogPath)
	}
	contents := renderPlist(binary, socketPath, logPath, extraArgs)

	for _, dir := range []string{filepath.Dir(socketPath), filepath.Dir(logPath)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := writePlistAtomically(plistPath, contents); err != nil {
		fatalf("write plist: %v", err)
	}
	fmt.Printf("Wrote plist: %s\n", plistPath)
	fmt.Printf("Binary:      %s\n", binary)
	fmt.Printf("Socket:      %s\n", socketPath)
	if auditLogPath != "" {
		fmt.Printf("Audit log:   %s\n", auditLogPath)
	}

	if noReload {
		fmt.Println("\nSkipping launchctl load (-no-reload). Load with:")
		fmt.Printf("    launchctl load %s\n", plistPath)
		return
	}
	if err := reloadPlist(plistPath, socketPath); err != nil {
		fatalf("reload: %v\n\nThe plist was written. Load it manually with:\n    launchctl load %s", err, plistPath)
	}
	fmt.Println("\nLoaded. Verify with:")
	fmt.Printf("    touchid-agent -status %s\n", socketPath)
}

// cmdMigratePlist rewrites an old-style plist to socket activation.
// Idempotent: no-op if already socket-activated.
func cmdMigratePlist(plistPath string, dryRun, noReload bool) {
	if plistPath == "" {
		plistPath = defaultPlistPath()
	}
	existing, err := readPlist(plistPath)
	if err != nil {
		fatalf("Could not read plist %s: %v", plistPath, err)
	}
	if existing == nil {
		fatalf("No plist found at %s. Use `touchid-agent -install-plist` for a fresh install.", plistPath)
	}
	if existing.Label != "" && existing.Label != plistLabel {
		fatalf("Plist at %s has Label=%q, refusing to migrate (expected %q).",
			plistPath, existing.Label, plistLabel)
	}
	switch existing.classify() {
	case plistModeSocketActivated:
		fmt.Printf("Plist at %s is already socket-activated — nothing to do.\n", plistPath)
		return
	case plistModeUnknown:
		fatalf("Plist at %s does not look like a touchid-agent -l-mode plist (no -l or -launchd in ProgramArguments). Inspect manually.", plistPath)
	}

	binary := resolveBinaryPath(existing)
	socketPath := defaultSocketPath()
	// Prefer the user's existing socket location if their old plist had -l PATH.
	if oldSock := socketFromOldArgs(existing.ProgramArguments); oldSock != "" {
		socketPath = oldSock
	}
	logPath := defaultLogPath()
	if existing.StandardErrorPath != "" {
		logPath = existing.StandardErrorPath
	} else if existing.StandardOutPath != "" {
		logPath = existing.StandardOutPath
	}
	extraArgs := extractRunFlags(existing.ProgramArguments)
	newContents := renderPlist(binary, socketPath, logPath, extraArgs)

	oldContents, err := os.ReadFile(plistPath)
	if err != nil {
		fatalf("read existing plist: %v", err)
	}

	if dryRun {
		fmt.Printf("--- %s (current)\n%s\n", plistPath, string(oldContents))
		fmt.Printf("+++ %s (proposed)\n%s\n", plistPath, newContents)
		fmt.Println("(dry-run: no changes written)")
		return
	}

	bk := backupPath(plistPath)
	if err := os.WriteFile(bk, oldContents, 0o600); err != nil {
		fatalf("write backup %s: %v", bk, err)
	}
	if err := writePlistAtomically(plistPath, newContents); err != nil {
		fatalf("write new plist: %v", err)
	}
	fmt.Printf("Backed up: %s\n", bk)
	fmt.Printf("Rewrote:   %s\n", plistPath)
	if len(extraArgs) > 0 {
		fmt.Printf("Preserved flags: %s\n", strings.Join(extraArgs, " "))
	}

	if noReload {
		fmt.Println("\nSkipping launchctl reload (-no-reload). Reload with:")
		fmt.Printf("    launchctl unload %s && launchctl load %s\n", plistPath, plistPath)
		return
	}
	if err := reloadPlist(plistPath, socketPath); err != nil {
		fatalf("reload: %v\n\nThe new plist is in place; the old one is at %s. Reload manually:\n    launchctl unload %s && launchctl load %s",
			err, bk, plistPath, plistPath)
	}
	fmt.Println("\nMigrated. Verify with:")
	fmt.Printf("    touchid-agent -status %s\n", socketPath)
}

// ensureAction describes what cmdEnsureUserPlist should do given the
// current state of the per-user plist.
type ensureAction int

const (
	ensureActionInstall       ensureAction = iota // no/missing plist → install one
	ensureActionAlreadyOK                         // already socket-activated → no-op
	ensureActionLeaveOldStyle                     // -l-mode plist present → leave alone, suggest -migrate-plist
	ensureActionLeaveUnknown                      // unrecognized layout → leave alone
)

// decideEnsureAction is the pure decision function that drives
// cmdEnsureUserPlist. Split out so it can be unit-tested without
// invoking launchctl.
func decideEnsureAction(existing *parsedPlist) ensureAction {
	if existing == nil {
		return ensureActionInstall
	}
	switch existing.classify() {
	case plistModeSocketActivated:
		return ensureActionAlreadyOK
	case plistModeOldStyle:
		return ensureActionLeaveOldStyle
	default:
		return ensureActionLeaveUnknown
	}
}

// cmdEnsureUserPlist is the entry point for the system-wide bootstrap
// LaunchAgent (`/Library/LaunchAgents/touchid-agent-bootstrap.plist`).
// It runs once per user GUI session and idempotently makes sure the
// per-user `~/Library/LaunchAgents/touchid-agent.plist` exists in
// socket-activated form. After the first session it is a no-op.
//
// Failures are written to stderr but never bubble up as a non-zero
// exit: the bootstrap plist would fire again on every login, and a
// noisy failure loop is worse than a single missed install (which
// the user can always recover via `touchid-agent -install-plist`).
func cmdEnsureUserPlist() {
	plistPath := defaultPlistPath()
	existing, err := readPlist(plistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ensure-user-plist: cannot read %s: %v\n", plistPath, err)
		return
	}
	switch decideEnsureAction(existing) {
	case ensureActionAlreadyOK:
		return
	case ensureActionLeaveOldStyle:
		fmt.Fprintf(os.Stderr,
			"ensure-user-plist: existing old-style plist at %s; leaving alone (run `touchid-agent -migrate-plist` to upgrade)\n",
			plistPath)
		return
	case ensureActionLeaveUnknown:
		fmt.Fprintf(os.Stderr,
			"ensure-user-plist: unrecognized plist at %s; leaving alone\n",
			plistPath)
		return
	case ensureActionInstall:
		cmdInstallPlist(plistPath, "", false)
	}
}

// socketFromOldArgs returns the value of -l from ProgramArguments, or "".
func socketFromOldArgs(args []string) string {
	for i, a := range args {
		if a == "-l" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// fatalf prints a message and exits 1. Mirrors log.Fatalf but writes to
// stderr without the log prefix, matching the rest of the CLI.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
