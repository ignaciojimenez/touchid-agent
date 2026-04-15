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
		fmt.Fprintf(os.Stderr, "  touchid-agent -create NAME [-no-touch] [-software]\n")
		fmt.Fprintf(os.Stderr, "        Create a new SSH key in the Secure Enclave.\n")
		fmt.Fprintf(os.Stderr, "        By default, Touch ID is required for every signing operation.\n")
		fmt.Fprintf(os.Stderr, "        Use -no-touch to allow signing without biometric confirmation.\n")
		fmt.Fprintf(os.Stderr, "        Use -software for a Keychain-backed key (no Secure Enclave).\n\n")
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
		cmdCreate(*createKey, !*noTouch, !*software)
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

func cmdCreate(label string, requireTouch bool, useSE bool) {
	if strings.Contains(label, ":") {
		log.Fatalln("Error: label must not contain ':'")
	}
	if label == "" {
		log.Fatalln("Error: label must not be empty")
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

func cmdRun(socketPath string) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: touchid-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd service.")
	}

	a := &Agent{}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			log.Println("Received HUP signal, refreshing key list on next request.")
		}
	}()

	os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0777); err != nil {
		log.Fatalln("Failed to create UNIX socket directory:", err)
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

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
