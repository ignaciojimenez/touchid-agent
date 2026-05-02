# TODO

## Done

- [x] Core agent: SSH agent protocol over Unix socket (ECDSA P-256)
- [x] Key management: create, list, delete, delete-all
- [x] Dual backend: Secure Enclave (hardware) and Keychain (software)
- [x] Per-key Touch ID policy (`-no-touch` flag)
- [x] Post-create hooks (`-post-hook` flag, env vars for provisioning)
- [x] Security hardening: socket 0600, dir 0700, graceful shutdown, stale
      socket detection, label validation, duplicate key prevention,
      osascript injection protection, connection idle timeout
- [x] Test suite: 54 tests with `-race`, mock KeyStore with real ECDSA signing
- [x] Shell completions (bash, zsh)
- [x] Example hooks (GitHub upload, GitHub signing)
- [x] Documentation: README, THREAT_MODEL, architecture, building, hooks,
      launchd, migration, git-signing
- [x] Verbose debug logging (`-v` flag)
- [x] Keychain error classification: actionable messages for locked
      Keychain, denied Touch ID, missing code signing, user cancellation

## Remaining

### 1. Code signing for Secure Enclave access

The binary must be signed with a Developer ID to create Secure Enclave keys
and enforce Touch ID on software keys. Software-backed keys with `-software
-no-touch` work with ad-hoc signing and are fully functional today.

```bash
make install CODESIGN_IDENTITY="Developer ID Application: ..."
./touchid-agent -create ssh   # SE key, Touch ID required
```

### 2. End-to-end signing verification

Validate the full chain with real Keychain keys: agent socket -> SSH client
-> remote sshd. Automated tests cover mock signing; this validates the
Security.framework DER-encoded ECDSA path.

### 3. Homebrew formula

Standard Go build formula with codesigning post-install step.


