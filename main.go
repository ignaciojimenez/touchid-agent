//go:build darwin

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

var Version string

func init() {
	if Version != "" {
		return
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		Version = buildInfo.Main.Version
		return
	}
	Version = "(unknown version)"
}

var debugLogger *log.Logger = log.New(io.Discard, "", 0)

func debugf(format string, args ...any) {
	debugLogger.Printf(format, args...)
}

func main() {
	fmt.Fprintf(os.Stderr, "\ntouchid-agent %s\n\n", Version)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -l PATH\n")
		fmt.Fprintf(os.Stderr, "        Run the agent, listening on the UNIX socket at PATH.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -launchd\n")
		fmt.Fprintf(os.Stderr, "        Run the agent using launchd socket activation.\n")
		fmt.Fprintf(os.Stderr, "        The socket is created and owned by launchd (see the plist Sockets key).\n")
		fmt.Fprintf(os.Stderr, "        The agent exits after %v of inactivity; launchd restarts it on demand.\n\n", launchdIdleTimeout)
		fmt.Fprintf(os.Stderr, "  touchid-agent -create NAME [-no-touch] [-post-hook CMD]\n")
		fmt.Fprintf(os.Stderr, "        Create a new SSH key in the Secure Enclave.\n")
		fmt.Fprintf(os.Stderr, "        By default, Touch ID is required for every signing operation.\n")
		fmt.Fprintf(os.Stderr, "        Use -no-touch to allow signing without biometric confirmation.\n")
		fmt.Fprintf(os.Stderr, "        Use -post-hook to run an executable after key creation.\n")
		fmt.Fprintf(os.Stderr, "        The value must be a path to an executable (not a shell expression).\n")
		fmt.Fprintf(os.Stderr, "        The executable receives key details via environment variables:\n")
		fmt.Fprintf(os.Stderr, "          TOUCHID_AGENT_LABEL, TOUCHID_AGENT_PUBKEY,\n")
		fmt.Fprintf(os.Stderr, "          TOUCHID_AGENT_PUBKEY_FILE, TOUCHID_AGENT_TOUCH_REQUIRED\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -list [-json]\n")
		fmt.Fprintf(os.Stderr, "        List all managed keys. Use -json for machine-readable output.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -delete NAME\n")
		fmt.Fprintf(os.Stderr, "        Delete the key with the given label.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -delete-all\n")
		fmt.Fprintf(os.Stderr, "        Delete all managed keys.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -status PATH\n")
		fmt.Fprintf(os.Stderr, "        Check if the agent at PATH is healthy. Exits 0 if reachable.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -install-plist [-audit-log PATH] [-no-reload]\n")
		fmt.Fprintf(os.Stderr, "        Write a launchd plist (socket activation) and load it.\n")
		fmt.Fprintf(os.Stderr, "        Idempotent; refuses to overwrite an old-style plist.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -migrate-plist [-dry-run] [-no-reload]\n")
		fmt.Fprintf(os.Stderr, "        Rewrite an existing -l-mode plist to socket activation,\n")
		fmt.Fprintf(os.Stderr, "        preserving -audit-log and other agent flags. Idempotent.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -ensure-user-plist\n")
		fmt.Fprintf(os.Stderr, "        Bootstrap helper invoked by the system-wide pkg's LaunchAgent.\n")
		fmt.Fprintf(os.Stderr, "        Equivalent to -install-plist but never errors out, so the\n")
		fmt.Fprintf(os.Stderr, "        bootstrap plist can fire on every login without spamming logs.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -version\n")
		fmt.Fprintf(os.Stderr, "        Print version and exit.\n\n")
		fmt.Fprintf(os.Stderr, "Optional flags for the agent (-l / -launchd) mode:\n")
		fmt.Fprintf(os.Stderr, "  -audit-log PATH         append a JSON-lines record per signing operation\n")
		fmt.Fprintf(os.Stderr, "  -peer-check             verify peer binary against allowlist for no-touch keys\n")
		fmt.Fprintf(os.Stderr, "  -rate-limit N           max signing operations per key per minute (ceiling: 120)\n")
		fmt.Fprintf(os.Stderr, "  -allowed-callers PATH   path to file listing additional allowed caller binaries\n")
		fmt.Fprintf(os.Stderr, "  -v                      enable verbose debug logging on stderr\n\n")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	launchdMode := flag.Bool("launchd", false, "agent: obtain listener from launchd socket activation")
	auditLogPath := flag.String("audit-log", "", "agent: path to JSON-lines audit log")
	peerCheck := flag.Bool("peer-check", false, "agent: verify peer binary against allowlist for no-touch keys")
	rateLimit := flag.Int("rate-limit", 0, "agent: max signing operations per key per minute (0=off, ceiling=120)")
	allowedCallersFile := flag.String("allowed-callers", "", "agent: path to file listing additional allowed caller binaries")
	createKey := flag.String("create", "", "create a new key with the given label")
	noTouch := flag.Bool("no-touch", false, "create: do not require Touch ID for this key")
	postHook := flag.String("post-hook", "", "create: run command after key creation")
	listKeys := flag.Bool("list", false, "list all managed keys")
	listJSON := flag.Bool("json", false, "list: output as JSON array")
	statusPath := flag.String("status", "", "check agent health at the given socket path")
	deleteKey := flag.String("delete", "", "delete the key with the given label")
	deleteAll := flag.Bool("delete-all", false, "delete all managed keys")
	verbose := flag.Bool("v", false, "enable verbose debug logging")
	showVersion := flag.Bool("version", false, "print version and exit")
	installPlist := flag.Bool("install-plist", false, "write launchd plist (socket activation) and load it")
	migratePlist := flag.Bool("migrate-plist", false, "rewrite an existing -l-mode plist to socket activation")
	ensureUserPlist := flag.Bool("ensure-user-plist", false, "bootstrap helper: idempotently install the per-user plist (used by the system-wide pkg)")
	plistPath := flag.String("plist", "", "plist path (defaults to ~/Library/LaunchAgents/touchid-agent.plist)")
	dryRun := flag.Bool("dry-run", false, "migrate-plist: print proposed plist without writing")
	noReload := flag.Bool("no-reload", false, "install-plist/migrate-plist: skip launchctl load/unload")

	flag.Parse()

	if *showVersion {
		fmt.Printf("touchid-agent %s\n", Version)
		return
	}

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	log.SetFlags(0)
	if *verbose {
		debugLogger = log.New(os.Stderr, "debug: ", log.Ltime)
	}

	// Plist subcommands do not need a key store and may run before the
	// agent has ever been used.
	if *installPlist {
		cmdInstallPlist(*plistPath, *auditLogPath, *noReload)
		return
	}
	if *migratePlist {
		cmdMigratePlist(*plistPath, *dryRun, *noReload)
		return
	}
	if *ensureUserPlist {
		cmdEnsureUserPlist()
		return
	}

	store, err := DefaultKeyStore()
	if err != nil {
		log.Fatalf("Failed to initialize key store: %v\n", err)
	}

	if *launchdMode && *socketPath != "" {
		log.Fatal("-launchd and -l are mutually exclusive")
	}

	switch {
	case *createKey != "":
		cmdCreate(store, *createKey, !*noTouch, *postHook)
	case *listKeys:
		cmdList(store, *listJSON)
	case *statusPath != "":
		cmdStatus(*statusPath)
	case *deleteKey != "":
		cmdDelete(store, *deleteKey)
	case *deleteAll:
		keys, err := store.List()
		if err != nil {
			log.Fatalf("Failed to list keys: %v\n", err)
		}
		if len(keys) == 0 {
			fmt.Println("No keys to delete.")
			return
		}
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Printf("Delete %d key(s)? [y/N] ", len(keys))
			var answer string
			fmt.Scanln(&answer)
			if answer != "y" && answer != "Y" {
				fmt.Println("Aborted.")
				return
			}
		}
		var labels []string
		for _, k := range keys {
			labels = append(labels, k.Label)
		}
		cmdDeleteAll(store, labels)
	case *launchdMode:
		cmdRun(store, "", true, *auditLogPath, *peerCheck, *rateLimit, *allowedCallersFile)
	case *socketPath != "":
		cmdRun(store, *socketPath, false, *auditLogPath, *peerCheck, *rateLimit, *allowedCallersFile)
	default:
		flag.Usage()
		os.Exit(1)
	}
}

func validateLabel(label string) error {
	if label == "" {
		return fmt.Errorf("label must not be empty")
	}
	if strings.Contains(label, ":") {
		return fmt.Errorf("label must not contain ':'")
	}
	if strings.ContainsAny(label, "/\\") {
		return fmt.Errorf("label must not contain path separators")
	}
	if len(label) > 64 {
		return fmt.Errorf("label must not exceed 64 characters")
	}
	return nil
}

func cmdCreate(store KeyStore, label string, requireTouch bool, postHookCmd string) {
	if err := validateLabel(label); err != nil {
		log.Fatalf("Error: %v\n", err)
	}

	key, err := store.Generate(label, requireTouch)
	if err != nil {
		log.Fatalf("Failed to generate key: %v\n", err)
	}

	if err := selfTestKey(key, requireTouch); err != nil {
		log.Fatalf("Key was generated but failed self-test: %v\n", err)
	}

	sshPub, err := ssh.NewPublicKey(key.publicKey)
	if err != nil {
		log.Fatalf("Failed to convert public key: %v\n", err)
	}

	pubKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	touchStr := "yes"
	if !requireTouch {
		touchStr = "no"
	}

	fmt.Printf("Key created: %s (Touch ID required: %s)\n\n", label, touchStr)
	fmt.Printf("SSH public key:\n%s touchid-agent:%s\n", pubKeyStr, label)

	pubFile := writePubKeyFile(label, pubKeyStr)

	if postHookCmd != "" {
		fmt.Printf("\nRunning post-create hook: %s\n", postHookCmd)
		if err := runPostHook(postHookCmd, label, pubKeyStr, pubFile, requireTouch); err != nil {
			log.Fatalf("Hook failed: %v\n", err)
		}
		fmt.Println("Hook completed successfully.")
	}
}

func selfTestKey(key *Key, requireTouch bool) error {
	if requireTouch {
		fmt.Fprintln(os.Stderr, "Confirming Touch ID enforcement (please authenticate)...")
	}
	digest := sha256.Sum256([]byte("touchid-agent: creation self-test"))
	sig, err := key.Sign(nil, digest[:], nil)
	if err != nil {
		return classifySignError(err)
	}
	if !ecdsa.VerifyASN1(key.publicKey, digest[:], sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func classifySignError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "userCancel") || strings.Contains(msg, "User cancel") || strings.Contains(msg, "LAError -2"):
		return fmt.Errorf("touch ID authentication was cancelled; the key was created successfully but not verified — run -list to confirm")
	case strings.Contains(msg, "biometryNotAvailable") || strings.Contains(msg, "LAError -6"):
		return fmt.Errorf("touch ID hardware is not available on this Mac; use -no-touch for a key without biometric confirmation")
	case strings.Contains(msg, "biometryNotEnrolled") || strings.Contains(msg, "LAError -7"):
		return fmt.Errorf("no fingerprints enrolled in Touch ID; enroll in System Settings > Touch ID, then retry")
	case strings.Contains(msg, "biometryLockout") || strings.Contains(msg, "LAError -8"):
		return fmt.Errorf("touch ID is locked out after too many failed attempts; unlock your Mac with your password to recover Touch ID, then retry — the key on disk is valid")
	case strings.Contains(msg, "passcodeNotSet") || strings.Contains(msg, "LAError -4"):
		return fmt.Errorf("no system password set; Touch ID requires a login password — set one in System Settings > Users & Groups")
	default:
		return fmt.Errorf("sign: %w", err)
	}
}

func writePubKeyFile(label, pubKeyStr string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: could not determine home directory: %v", err)
		return ""
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		log.Printf("Warning: could not create %s: %v", sshDir, err)
		return ""
	}
	pubFile := filepath.Join(sshDir, fmt.Sprintf("touchid-agent-%s.pub", label))
	content := fmt.Sprintf("%s touchid-agent:%s\n", pubKeyStr, label)
	if err := os.WriteFile(pubFile, []byte(content), 0644); err != nil {
		log.Printf("Warning: could not write public key file: %v", err)
		return ""
	}
	fmt.Printf("\nPublic key written to: %s\n", pubFile)
	return pubFile
}

func removePubKeyFile(label string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	pubFile := filepath.Join(home, ".ssh", fmt.Sprintf("touchid-agent-%s.pub", label))
	if err := os.Remove(pubFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("Warning: could not remove public key file %s: %v", pubFile, err)
	}
}

func runPostHook(hookCmd, label, pubKeyStr, pubFile string, touchRequired bool) error {
	if hookCmd == "" {
		return nil
	}
	cmd := exec.Command(hookCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TOUCHID_AGENT_LABEL=%s", label),
		fmt.Sprintf("TOUCHID_AGENT_PUBKEY=%s touchid-agent:%s", pubKeyStr, label),
		fmt.Sprintf("TOUCHID_AGENT_PUBKEY_FILE=%s", pubFile),
		fmt.Sprintf("TOUCHID_AGENT_TOUCH_REQUIRED=%s", strconv.FormatBool(touchRequired)),
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("post-create hook failed: %w", err)
	}
	return nil
}

type keyListEntry struct {
	Label        string `json:"label"`
	RequireTouch bool   `json:"require_touch"`
	PublicKey    string `json:"public_key"`
}

func cmdList(store KeyStore, jsonOutput bool) {
	keys, err := store.List()
	if err != nil {
		log.Fatalf("Failed to list keys: %v\n", err)
	}

	if jsonOutput {
		var entries []keyListEntry
		for _, k := range keys {
			sshPub, err := ssh.NewPublicKey(k.publicKey)
			if err != nil {
				continue
			}
			entries = append(entries, keyListEntry{
				Label:        k.Label,
				RequireTouch: k.RequireTouch,
				PublicKey:    strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
			})
		}
		if entries == nil {
			entries = []keyListEntry{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(entries)
		return
	}

	if len(keys) == 0 {
		fmt.Println("No keys found.")
		return
	}

	for _, k := range keys {
		sshPub, err := ssh.NewPublicKey(k.publicKey)
		if err != nil {
			continue
		}
		pubKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

		touchStr := "yes"
		if !k.RequireTouch {
			touchStr = "no"
		}

		fmt.Printf("%-16s Touch ID: %-3s  %s\n", k.Label, touchStr, pubKeyStr)
	}
}

func cmdDelete(store KeyStore, label string) {
	if err := validateLabel(label); err != nil {
		log.Fatalf("Error: %v\n", err)
	}
	if err := store.Delete(label); err != nil {
		log.Fatalf("Failed to delete key: %v\n", err)
	}
	removePubKeyFile(label)
	fmt.Printf("Key '%s' deleted.\n", label)
}

func cmdDeleteAll(store KeyStore, labels []string) {
	if err := store.DeleteAll(); err != nil {
		log.Fatalf("Failed to delete keys: %v\n", err)
	}
	for _, label := range labels {
		removePubKeyFile(label)
	}
	fmt.Println("All keys deleted.")
}

func cmdStatus(socketPath string) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Agent unreachable: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Agent error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Agent is running. %d key(s) available.\n", len(keys))

	if pids := findStaleLModeProcesses(socketPath, os.Getpid()); len(pids) > 0 {
		fmt.Fprintf(os.Stderr, "\nWarning: detected %d touchid-agent process(es) running with -l on the same socket: %v\n", len(pids), pids)
		fmt.Fprintln(os.Stderr, "This usually means an old plist is still loaded. Consider:")
		fmt.Fprintln(os.Stderr, "    touchid-agent -migrate-plist")
	}
}

// findStaleLModeProcesses returns PIDs of touchid-agent processes
// running with `-l SAMESOCKET`, excluding selfPid. Used by -status to
// warn about an old `-l`-mode agent still loaded after a migration.
// Returns nil on error or no matches.
func findStaleLModeProcesses(socketPath string, selfPid int) []int {
	out, err := exec.Command("/bin/ps", "-axo", "pid=,command=").Output()
	if err != nil {
		return nil
	}
	return parseStaleLModeProcesses(string(out), socketPath, selfPid)
}

// parseStaleLModeProcesses parses `ps -axo pid=,command=` output and
// returns PIDs of touchid-agent processes invoking `-l socketPath`,
// excluding selfPid. Pure-function for testability.
func parseStaleLModeProcesses(psOutput, socketPath string, selfPid int) []int {
	var pids []int
	for _, line := range strings.Split(psOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, " ", 2)
		if len(fields) != 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid == selfPid {
			continue
		}
		cmd := fields[1]
		toks := strings.Fields(cmd)
		if len(toks) == 0 || filepath.Base(toks[0]) != "touchid-agent" {
			continue
		}
		for i, t := range toks {
			if t == "-l" && i+1 < len(toks) && toks[i+1] == socketPath {
				pids = append(pids, pid)
				break
			}
		}
	}
	return pids
}

const launchdIdleTimeout = 10 * time.Minute

func cmdRun(store KeyStore, socketPath string, launchd bool, auditLogPath string, peerCheck bool, rateLimit int, allowedCallersFile string) {
	if !launchd && term.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: touchid-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd service.")
	}

	var audit *AuditLogger
	if auditLogPath != "" {
		var err error
		audit, err = NewAuditLogger(auditLogPath)
		if err != nil {
			log.Fatalf("Failed to open audit log: %v\n", err)
		}
		log.Printf("Audit log enabled: %s", auditLogPath)
	} else {
		audit = NewStderrAuditLogger()
	}

	var extraCallers []string
	if allowedCallersFile != "" {
		var err error
		extraCallers, err = loadAllowedCallers(allowedCallersFile)
		if err != nil {
			log.Fatalf("Failed to load allowed callers: %v\n", err)
		}
	}
	policy := NewPeerPolicy(peerCheck, rateLimit, extraCallers)
	if peerCheck {
		log.Printf("Peer verification enabled (%d allowed caller paths)", len(policy.allowedPaths))
	}
	if rateLimit > 0 {
		log.Printf("Rate limiting enabled: %d/min per key (ceiling: %d)", policy.rateLimit, rateLimitCeiling)
	}

	a := &Agent{store: store, audit: audit, policy: policy}

	var l net.Listener
	if launchd {
		var err error
		l, err = launchdListener()
		if err != nil {
			log.Fatalf("Failed to activate launchd socket: %v\n", err)
		}
		log.Printf("Listening via launchd socket activation (idle timeout: %v)", launchdIdleTimeout)
	} else {
		os.Remove(socketPath)
		if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
			log.Fatalln("Failed to create UNIX socket directory:", err)
		}
		oldMask := syscall.Umask(0077)
		var err error
		l, err = net.Listen("unix", socketPath)
		syscall.Umask(oldMask)
		if err != nil {
			log.Fatalln("Failed to listen on UNIX socket:", err)
		}
		if err := os.Chmod(socketPath, 0600); err != nil {
			log.Printf("Warning: could not set socket permissions: %v", err)
		}
		log.Printf("Listening on %s\n", socketPath)
	}

	// Signal handling: close the listener so the accept loop exits,
	// then let normal control flow drain connections and run cleanup.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				log.Println("Received HUP signal, ignored (no persistent state to refresh).")
				continue
			}
			log.Printf("Received %s, shutting down.", sig)
			l.Close()
			return
		}
	}()

	// In launchd mode, exit after a period of inactivity so launchd can
	// restart us on demand. This keeps the idle footprint at zero.
	var idleTimer *time.Timer
	if launchd {
		idleTimer = time.AfterFunc(launchdIdleTimeout, func() {
			log.Println("Idle timeout reached, exiting for launchd to restart on demand.")
			l.Close()
		})
	}

	var wg sync.WaitGroup
	for {
		conn, err := l.Accept()
		if err != nil {
			if launchd {
				debugf("accept loop ended: %v", err)
				break
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			// Listener closed by signal or other fatal error.
			break
		}
		if idleTimer != nil {
			idleTimer.Reset(launchdIdleTimeout)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.serveConn(conn)
		}()
	}

	log.Println("Waiting for active connections to finish...")
	wg.Wait()

	if !launchd {
		os.Remove(socketPath)
	}
	audit.Close()
	log.Println("Shutdown complete.")
}
