# Architecture

```
main.go                  CLI and daemon entrypoint
agent.go                 SSH agent protocol implementation
hook.go                  Post-create hook execution
keystore.go              KeyStore interface (testability boundary)
secureenclave_darwin.go  Go/CGo bridge to Security.framework
secureenclave.m          Objective-C: key generation, signing, listing, deletion
notify_darwin.go         Touch ID reminder notification
contrib/hooks/           Example provisioning hooks (GitHub, etc.)
contrib/completions/     Shell completions (bash, zsh)
contrib/plist/           launchd service template
```

## Design principles

| Principle | Implementation |
|-----------|---------------|
| Keys never leave hardware | Generated in and used by the Secure Enclave (ECDSA P-256). |
| Per-operation authentication | Touch ID required for each signing request (configurable per key). |
| Drop-in replacement | Standard SSH agent protocol. Set `SSH_AUTH_SOCK` and go. |
| Multiple named keys | One key per purpose (e.g., `ssh` for auth, `git` for signing). |
| No secrets in memory | All signing delegated to Security.framework; agent holds no key material. |
| macOS only | By design. The Secure Enclave is Apple hardware. |
