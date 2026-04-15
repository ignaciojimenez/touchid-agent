# touchid-agent: Status and Next Steps

## What Exists (v0.1 - done)

A working SSH agent for macOS that stores ECDSA P-256 keys in Keychain
(Secure Enclave or software-backed) with optional per-key Touch ID policy.

### Architecture

```
main.go                  CLI entrypoint: -create, -list, -delete, -delete-all, -l (run agent)
agent.go                 SSH agent protocol (golang.org/x/crypto/ssh/agent)
secureenclave_darwin.go  Go/CGo wrappers around Keychain operations
secureenclave.m          Objective-C: key gen, sign, list, delete via Security.framework
secureenclave.h          C header for the above
notify_darwin.go         macOS notification via osascript
Makefile                 Build with optional CODESIGN_IDENTITY
contrib/plist/           launchd plist template
```

### What was tested

| Test | Result |
|------|--------|
| `go build` | Clean, no warnings |
| `go vet` | Pass |
| `-create NAME -no-touch -software` | Key generated, pub written to ~/.ssh/ |
| `-list` | Shows key label, touch policy, pubkey |
| Agent via `-l SOCKET` + `ssh-add -L` | Key visible through agent |
| Agent signing (SSH to github.com) | Sign attempted, rejected (key not registered) |
| `-delete NAME` | Key removed from Keychain |
| Full lifecycle: create -> list -> serve -> sign -> delete | Pass |

### What was NOT tested (needs a signing identity)

| Test | Blocker |
|------|---------|
| Secure Enclave key creation (`-create` without `-software`) | Requires Developer ID signing identity |
| Touch ID prompt (`-create` without `-no-touch`) | Requires SE key + signed binary |
| Touch ID notification after 3s delay | Requires interactive Touch ID session |
| Production SSH session (connect, authenticate, shell) | Requires key registered on server |
| Git commit signing with touchid-agent key | Needs `.gitconfig` setup + key on git server |
| launchd service lifecycle (start, stop, reboot) | Manual testing required |
| Multiple keys simultaneously | Untested but architecturally supported |

---

## Next Steps (Priority Order)

### 1. Code signing for Secure Enclave access

The binary **must** be signed with a Developer ID to access the Secure Enclave.
Software-backed keys (`-software`) work with ad-hoc signing.

Options:
- Obtain an Apple Developer account ($99/yr) and create a Developer ID certificate
- Distribute via Homebrew cask with notarization
- For Adyen: sign with the corporate Apple Enterprise certificate

To test: `make CODESIGN_IDENTITY="Developer ID Application: ..."` then
`./touchid-agent -create mykey` (without `-software`).

### 2. Proper signing verification

The current `Sign` implementation in `agent.go` calls `signer.Sign(rand.Reader, data)`
which uses `ssh.NewSignerFromKey`. This works because `SEKey` implements `crypto.Signer`,
but the SSH agent protocol also needs `SignWithFlags` to support algorithm negotiation
(RSA SHA-256/512). Since we only generate ECDSA P-256 keys, this is fine, but verify that:
- SHA-256 digest handling is correct end-to-end
- The DER-encoded ECDSA signature from Security.framework is correctly interpreted by
  `golang.org/x/crypto/ssh`

Test: create a key, add the pubkey to a test server's `authorized_keys`, SSH in.

### 3. README

The project currently has no README. Needs:
- What it is and why (one paragraph)
- Installation (build from source, Homebrew if published)
- Usage examples for all commands
- Code signing requirements
- Comparison to yubikey-agent, Secretive, sekey
- Security model (non-exportable keys, Touch ID policies, Keychain storage)

### 4. Homebrew formula

For distribution. Standard Go build formula with codesigning post-install.

### 5. Edge cases and hardening

- **Agent reconnection**: if Keychain is locked (screen lock timeout), signing will fail.
  The current code does not retry or show a helpful error. Consider catching
  `errSecAuthFailed` / `errSecInteractionNotAllowed` and prompting.
- **Multiple agents**: warn or fail if another instance is already listening on the socket.
- **Key collision**: `-create` should check if a key with the same label already exists
  and refuse (or offer `-force`).
- **Signal handling**: SIGTERM should clean up the socket file.
- **Logging**: currently minimal. Consider `-v` flag for debug logging.

### 6. Tests

No automated tests exist yet. Priority:
- Unit tests for tag encoding/parsing (`makeTag`, `parseTag`)
- Integration test for key lifecycle (requires Keychain access, so platform-specific)
- Agent protocol tests with mock signer

---

## Adyen Migration Context

This project is designed as a **generic open-source tool** (no Adyen-specific code).
Adyen adoption would require a separate wrapper or extension for:

| Concern | Where it lives today (yubikey-agent) | What Adyen needs to build |
|---------|--------------------------------------|--------------------------|
| LDAP authentication | `setup.go` `SSHKeyImporter()` | Separate CLI or wrapper script |
| SSH Key Importer API upload | `setup.go` POST to `desktopmgt.is.adyen.com` | Same wrapper, extended API payload |
| Puppet integration | Puppet writes `~/.ssh/yubikey9a*` files | Update Puppet to write `~/.ssh/touchid-agent-*.pub` |
| launchd management | Puppet deploys plist + brew services | Update to use `contrib/plist/touchid-agent.plist` |
| User opt-in | `touch ~/.ssh/enable_yubikey_agent` | New flag file or same mechanism |
| Git signing | `.gitconfig signingkey=~/.ssh/yubikey9e` | Change to `~/.ssh/touchid-agent-<label>.pub` |

### Two-key model at Adyen

The yubikey-agent uses PIV slots with different touch policies:

| Slot | PIV Name | Touch | PIN | Used for |
|------|----------|-------|-----|----------|
| 9a | Authentication | Always | Once per session | SSH to servers, SCP |
| 9e | CardAuthentication | Never | Once per session | Git operations, signing |

Equivalent touchid-agent setup:
```bash
touchid-agent -create ssh       # Touch ID required per sign (default)
touchid-agent -create git -no-touch  # No Touch ID, available when Mac is unlocked
```

### Migration phases (from original spec)

1. **API extension**: SSH Key Importer accepts both yubikey and touchid key payloads
2. **Pilot**: IS team tests with clean switchover per user
3. **Gradual rollout**: Self Service, users opt in, old keys remain valid
4. **Deprecation**: stop issuing YubiKeys, remove yubikey-agent from fleet
