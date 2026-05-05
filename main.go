//go:build darwin

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
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
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
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
		fmt.Fprintf(os.Stderr, "  touchid-agent -create NAME [-no-touch] [-post-hook CMD]\n")
		fmt.Fprintf(os.Stderr, "        Create a new SSH key in the Secure Enclave.\n")
		fmt.Fprintf(os.Stderr, "        By default, Touch ID is required for every signing operation.\n")
		fmt.Fprintf(os.Stderr, "        Use -no-touch to allow signing without biometric confirmation.\n")
		fmt.Fprintf(os.Stderr, "        Use -post-hook to run an executable after key creation.\n")
		fmt.Fprintf(os.Stderr, "        The value must be a path to an executable (not a shell expression).\n")
		fmt.Fprintf(os.Stderr, "        The executable receives key details via environment variables:\n")
		fmt.Fprintf(os.Stderr, "          TOUCHID_AGENT_LABEL, TOUCHID_AGENT_PUBKEY,\n")
		fmt.Fprintf(os.Stderr, "          TOUCHID_AGENT_PUBKEY_FILE, TOUCHID_AGENT_TOUCH_REQUIRED\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -list\n")
		fmt.Fprintf(os.Stderr, "        List all managed keys.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -delete NAME\n")
		fmt.Fprintf(os.Stderr, "        Delete the key with the given label.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -delete-all\n")
		fmt.Fprintf(os.Stderr, "        Delete all managed keys.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -version\n")
		fmt.Fprintf(os.Stderr, "        Print version and exit.\n\n")
		fmt.Fprintf(os.Stderr, "Optional flags for the agent (-l) mode:\n")
		fmt.Fprintf(os.Stderr, "  -audit-log PATH   append a JSON-lines record per signing operation\n")
		fmt.Fprintf(os.Stderr, "  -v                enable verbose debug logging on stderr\n\n")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	auditLogPath := flag.String("audit-log", "", "agent: path to JSON-lines audit log")
	createKey := flag.String("create", "", "create a new key with the given label")
	noTouch := flag.Bool("no-touch", false, "create: do not require Touch ID for this key")
	postHook := flag.String("post-hook", "", "create: run command after key creation")
	listKeys := flag.Bool("list", false, "list all managed keys")
	deleteKey := flag.String("delete", "", "delete the key with the given label")
	deleteAll := flag.Bool("delete-all", false, "delete all managed keys")
	verbose := flag.Bool("v", false, "enable verbose debug logging")
	showVersion := flag.Bool("version", false, "print version and exit")

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

	store, err := DefaultKeyStore()
	if err != nil {
		log.Fatalf("Failed to initialize key store: %v\n", err)
	}

	switch {
	case *createKey != "":
		cmdCreate(store, *createKey, !*noTouch, *postHook)
	case *listKeys:
		cmdList(store)
	case *deleteKey != "":
		cmdDelete(store, *deleteKey)
	case *deleteAll:
		cmdDeleteAll(store)
	case *socketPath != "":
		cmdRun(store, *socketPath, *auditLogPath)
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
		return fmt.Errorf("Touch ID authentication was cancelled; the key was created successfully but not verified — run -list to confirm")
	case strings.Contains(msg, "biometryNotAvailable") || strings.Contains(msg, "LAError -6"):
		return fmt.Errorf("Touch ID hardware is not available on this Mac; use -no-touch for a key without biometric confirmation")
	case strings.Contains(msg, "biometryNotEnrolled") || strings.Contains(msg, "LAError -7"):
		return fmt.Errorf("no fingerprints enrolled in Touch ID; enroll in System Settings > Touch ID, then retry")
	case strings.Contains(msg, "biometryLockout") || strings.Contains(msg, "LAError -8"):
		return fmt.Errorf("Touch ID is locked out after too many failed attempts; unlock your Mac with your password to recover Touch ID, then retry — the key on disk is valid")
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

func cmdList(store KeyStore) {
	keys, err := store.List()
	if err != nil {
		log.Fatalf("Failed to list keys: %v\n", err)
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
	fmt.Printf("Key '%s' deleted.\n", label)
}

func cmdDeleteAll(store KeyStore) {
	if err := store.DeleteAll(); err != nil {
		log.Fatalf("Failed to delete keys: %v\n", err)
	}
	fmt.Println("All keys deleted.")
}

func cmdRun(store KeyStore, socketPath, auditLogPath string) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
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
	}

	a := &Agent{store: store, audit: audit}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		log.Fatalln("Failed to create UNIX socket directory:", err)
	}
	oldMask := syscall.Umask(0077)
	l, err := net.Listen("unix", socketPath)
	syscall.Umask(oldMask)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		log.Printf("Warning: could not set socket permissions: %v", err)
	}

	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				log.Println("Received HUP signal, ignored (no persistent state to refresh).")
				continue
			}
			log.Printf("Received %s, shutting down.", sig)
			l.Close()
			os.Remove(socketPath)
			audit.Close()
			os.Exit(0)
		}
	}()

	log.Printf("Listening on %s\n", socketPath)

	for {
		conn, err := l.Accept()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(conn)
	}
}
