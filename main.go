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
	"os/signal"
	"path/filepath"
	"runtime/debug"
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
		fmt.Fprintf(os.Stderr, "  touchid-agent -create NAME [-no-touch] [-software] [-post-hook CMD]\n")
		fmt.Fprintf(os.Stderr, "        Create a new SSH key in the Secure Enclave.\n")
		fmt.Fprintf(os.Stderr, "        By default, Touch ID is required for every signing operation.\n")
		fmt.Fprintf(os.Stderr, "        Use -no-touch to allow signing without biometric confirmation.\n")
		fmt.Fprintf(os.Stderr, "        Use -software for a Keychain-backed key (no Secure Enclave).\n")
		fmt.Fprintf(os.Stderr, "        Use -post-hook to run a command after key creation. The command\n")
		fmt.Fprintf(os.Stderr, "        receives key details via environment variables:\n")
		fmt.Fprintf(os.Stderr, "          TOUCHID_AGENT_LABEL, TOUCHID_AGENT_PUBKEY,\n")
		fmt.Fprintf(os.Stderr, "          TOUCHID_AGENT_PUBKEY_FILE, TOUCHID_AGENT_TOUCH_REQUIRED\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -list\n")
		fmt.Fprintf(os.Stderr, "        List all managed keys.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -delete NAME\n")
		fmt.Fprintf(os.Stderr, "        Delete the key with the given label.\n\n")
		fmt.Fprintf(os.Stderr, "  touchid-agent -delete-all\n")
		fmt.Fprintf(os.Stderr, "        Delete all managed keys.\n\n")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	createKey := flag.String("create", "", "create a new key with the given label")
	noTouch := flag.Bool("no-touch", false, "create: do not require Touch ID for this key")
	software := flag.Bool("software", false, "create: use software-backed Keychain key instead of Secure Enclave")
	postHook := flag.String("post-hook", "", "create: run command after key creation")
	listKeys := flag.Bool("list", false, "list all managed keys")
	deleteKey := flag.String("delete", "", "delete the key with the given label")
	deleteAll := flag.Bool("delete-all", false, "delete all managed keys")
	verbose := flag.Bool("v", false, "enable verbose debug logging")

	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	log.SetFlags(0)
	if *verbose {
		debugLogger = log.New(os.Stderr, "debug: ", log.Ltime)
	}

	if *createKey != "" {
		if err := validateCreateFlags(*software, *noTouch); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	store, err := DefaultKeyStore()
	if err != nil {
		log.Fatalf("Failed to initialize key store: %v\n", err)
	}

	switch {
	case *createKey != "":
		cmdCreate(store, *createKey, !*noTouch, !*software, *postHook)
	case *listKeys:
		cmdList(store)
	case *deleteKey != "":
		cmdDelete(store, *deleteKey)
	case *deleteAll:
		cmdDeleteAll(store)
	case *socketPath != "":
		cmdRun(store, *socketPath)
	default:
		flag.Usage()
		os.Exit(1)
	}
}

// validateCreateFlags rejects the only disallowed flag combo: -software
// without -no-touch. Touch ID enforcement on software keys would require
// a custom encryption-with-LAContext scheme; the trade-off is not worth
// it because users wanting biometry already get the strictly-better
// SE-backed default.
func validateCreateFlags(software, noTouch bool) error {
	if software && !noTouch {
		return errors.New(
			"-software requires -no-touch (Touch ID is not supported on " +
				"software-backed keys; use the default -create for an SE key " +
				"with Touch ID enforced by the Secure Enclave Processor)")
	}
	return nil
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

func cmdCreate(store KeyStore, label string, requireTouch bool, useSE bool, postHookCmd string) {
	if err := validateLabel(label); err != nil {
		log.Fatalf("Error: %v\n", err)
	}

	key, err := store.Generate(label, requireTouch, useSE)
	if err != nil {
		log.Fatalf("Failed to generate key: %v\n", err)
	}

	if err := selfTestKey(key, requireTouch); err != nil {
		log.Fatalf("Key was generated but failed self-test: %v\n"+
			"The key is unusable; this likely indicates a bug. Please report.\n", err)
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
		hookEnv := HookEnv{
			Label:         label,
			PubKey:        fmt.Sprintf("%s touchid-agent:%s", pubKeyStr, label),
			PubKeyFile:    pubFile,
			TouchRequired: requireTouch,
		}
		if err := runPostHook(postHookCmd, hookEnv); err != nil {
			log.Fatalf("Hook failed: %v\n", err)
		}
		fmt.Println("Hook completed successfully.")
	}
}

// selfTestKey signs a fixed digest with the freshly generated key and
// verifies the signature locally. Forces a Touch ID prompt for biometry-
// gated keys (the user expects this ceremony at create time) and proves
// end-to-end that the access control + signing path are wired correctly
// before we tell the user the key is ready to use.
func selfTestKey(key *SEKey, requireTouch bool) error {
	if requireTouch {
		fmt.Fprintln(os.Stderr, "Confirming Touch ID enforcement (please authenticate)...")
	}
	digest := sha256.Sum256([]byte("touchid-agent: creation self-test"))
	sig, err := key.Sign(nil, digest[:], nil)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if !ecdsa.VerifyASN1(key.publicKey, digest[:], sig) {
		return errors.New("signature verification failed")
	}
	return nil
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

func isSocketInUse(path string) bool {
	conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func cmdRun(store KeyStore, socketPath string) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: touchid-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd service.")
	}

	// H8: Check for another running instance before replacing the socket.
	if isSocketInUse(socketPath) {
		log.Fatalf("Another agent is already listening on %s\n", socketPath)
	}

	a := &Agent{store: store}

	// H2: Graceful shutdown on SIGTERM/SIGINT; SIGHUP refreshes.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		log.Fatalln("Failed to create UNIX socket directory:", err)
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

	// H1: Restrict socket permissions to owner only.
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
