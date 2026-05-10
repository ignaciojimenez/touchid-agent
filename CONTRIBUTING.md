# Contributing

## Project overview

macOS SSH agent backed by the Secure Enclave and Touch ID. Drop-in
replacement for yubikey-agent. darwin-only by design; the cgo bridge
links a Swift static library that talks to the SEP through CryptoKit.

## Key constraints

- **darwin-only** — build tag `//go:build darwin` on all source files;
  will not compile elsewhere.
- **Swift toolchain required** — `secureenclave.swift` is compiled to
  `libsecureenclave.a` by `swiftc` (Xcode Command Line Tools provides
  it). `make build` runs the Swift step before `go build`.
- **Cgo required** — `secureenclave_darwin.go` bridges to the static
  Swift archive via cgo and the `secureenclave_bridge.h` header.
- **macOS 11+** — CryptoKit's `SecureEnclave.P256` API needs that
  deployment target; we set it explicitly via `-target *-apple-macos11`.
- **Code signing** — ad-hoc signing (default) works for development.
  Developer ID signing is required for Secure Enclave keys;
  **no entitlements** are used.
- **No test for real SE** — `keystore_mock_test.go` provides a mock
  `KeyStore` with real ECDSA signing for unit tests; SE-backed flows
  are exercised manually after `make sign CODESIGN_IDENTITY="..."`.

## Prerequisites

- macOS 11 or later (CryptoKit's `SecureEnclave.P256` API)
- Xcode Command Line Tools (provides `swiftc`)
- Go 1.21 or later

## Build and test commands

```bash
make build          # swiftc + go build
make test           # go test -v -race -count=1 ./... (depends on libsecureenclave.a)
make install        # build + codesign + install to /usr/local/bin
make test-cover     # run tests + generate coverage.html
make clean          # remove build artifacts (binary, .a, .swiftmodule, etc.)
```

### Build variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CODESIGN_IDENTITY` | `-` (ad-hoc) | Code signing identity. Set to a Developer ID for production. |
| `PREFIX` | `/usr/local` | Install prefix for `make install`. |
| `VERSION` | `git describe` | Version string embedded in the binary. |

### Code signing

Ad-hoc signing (the default) works for development and tests. Secure
Enclave key creation requires a Developer ID-signed binary. **No
entitlements** are claimed; the SEP is reached via CryptoKit.

```bash
make install CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
```

List available signing identities:

```bash
security find-identity -v -p codesigning
```

### Quick run

```bash
./touchid-agent -l /tmp/.touchid-agent.sock
export SSH_AUTH_SOCK=/tmp/.touchid-agent.sock
```

## Architecture

```
main.go                  CLI, daemon lifecycle, post-create hooks
agent.go                 SSH agent protocol, notifications
keystore_fs.go           KeyStore interface + filesystem implementation
secureenclave.swift      CryptoKit bridge: SE P-256
secureenclave_bridge.h   Cgo / Swift C ABI
secureenclave_darwin.go  Go side of the cgo bridge, Key type
contrib/hooks/           Example provisioning hooks (GitHub, etc.)
contrib/completions/     Shell completions (bash, zsh)
contrib/plist/           launchd service template
```

See `docs/THREAT_MODEL.md` for the security model.

### Architecture and Coding Strategy Decisions

- **Storage layout**: Keys are persisted as SEP-wrapped data blobs in `~/.touchid-agent/keys/` with mode 0600.
- **CryptoKit over Security framework**: By using CryptoKit we bypass the data-protection keychain and avoid needing entitlements, allowing a flat Developer-ID-signed Mach-O.
- **Drop-in replacement**: We expose a standard SSH agent protocol socket (`SSH_AUTH_SOCK`) to work identically to `yubikey-agent`.
- **Per-operation authentication**: Touch ID is forced per signing request (unless explicitly opted out) via `.biometryAny` access control.
- **macOS only**: Tied strictly to Apple's Secure Enclave.
- **Enterprise readiness**: Tracked as a separate roadmap in `docs/distribution-roadmap.md`. Do not mix enterprise deployment features into the core daily usage docs until completed.

## Testing

- All tests use the race detector: `make test`.
- `keystore_mock_test.go` provides a mock `KeyStore` with real ECDSA
  signing (no SE needed). Most agent / CLI tests use it.
- `keystore_fs_test.go` covers the filesystem store, including
  malformed-JSON skipping and label/filename mismatch rejection.
- `agent_integration_test.go` covers the full agent-socket path with
  the mock store.
- SE-dependent flows (Touch ID prompts, end-to-end SSH) require a
  Developer-ID-signed binary on a Mac with an SEP. Run them manually.

## Shell Completions

When adding, removing, or renaming CLI flags in `main.go`, update the
shell completion scripts to stay in sync:

- `contrib/completions/touchid-agent.bash` — update `_touchid_agent_flags`
  and the `case` statement for flags that take values.
- `contrib/completions/touchid-agent.zsh` — update the `_arguments` list.

Flags that accept a value (e.g. `-create NAME`) need special handling in
both scripts: bash needs a `case` entry to suppress file completion, zsh
needs a `:description:` suffix on the argument spec.
