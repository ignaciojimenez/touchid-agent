//go:build darwin

package main

import (
	"flag"
	"fmt"
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

	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	log.SetFlags(0)

	switch {
	case *createKey != "":
		cmdCreate(*createKey, !*noTouch, !*software, *postHook)
	case *listKeys:
		cmdList()
	case *deleteKey != "":
		cmdDelete(*deleteKey)
	case *deleteAll:
		cmdDeleteAll()
	case *socketPath != "":
		cmdRun(*socketPath)
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

func cmdCreate(label string, requireTouch bool, useSE bool, postHookCmd string) {
	if err := validateLabel(label); err != nil {
		log.Fatalf("Error: %v\n", err)
	}

	// H3: Refuse to create if a key with the same label exists.
	existing, err := ListSEKeys()
	if err == nil {
		for _, k := range existing {
			if k.Label == label {
				log.Fatalf("Error: key with label '%s' already exists. Delete it first or choose a different name.\n", label)
			}
		}
	}

	key, err := GenerateSEKey(label, requireTouch, useSE)
	if err != nil {
		log.Fatalf("Failed to generate key: %v\n", err)
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

	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0700)
	pubFile := filepath.Join(sshDir, fmt.Sprintf("touchid-agent-%s.pub", label))
	content := fmt.Sprintf("%s touchid-agent:%s\n", pubKeyStr, label)
	if err := os.WriteFile(pubFile, []byte(content), 0644); err != nil {
		log.Printf("Warning: could not write public key file: %v", err)
	} else {
		fmt.Printf("\nPublic key written to: %s\n", pubFile)
	}

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

func cmdList() {
	keys, err := ListSEKeys()
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

func cmdDelete(label string) {
	if err := DeleteSEKey(label); err != nil {
		log.Fatalf("Failed to delete key: %v\n", err)
	}
	fmt.Printf("Key '%s' deleted.\n", label)
}

func cmdDeleteAll() {
	if err := DeleteAllSEKeys(); err != nil {
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

func cmdRun(socketPath string) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: touchid-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd service.")
	}

	// H8: Check for another running instance before replacing the socket.
	if isSocketInUse(socketPath) {
		log.Fatalf("Another agent is already listening on %s\n", socketPath)
	}

	a := &Agent{store: &RealKeyStore{}}

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
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(conn)
	}
}
