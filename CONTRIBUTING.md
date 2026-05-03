# Contributing

## Project overview

macOS SSH agent backed by the Secure Enclave and Touch ID. Drop-in replacement
for yubikey-agent. darwin-only by design; requires CGo (Objective-C bridge to
Security.framework).

## Key constraints

- **darwin-only** — build tag `//go:build darwin` on all source files; will not compile elsewhere
- **CGo required** — `secureenclave_darwin.go` bridges to `secureenclave.m` via CGo
- **Code signing** — ad-hoc signing (default) only supports `-software -no-touch` keys;
  Developer ID signing is required for Secure Enclave keys and Touch ID enforcement on software keys
- **No test for real Keychain/SE** — `keystore_mock_test.go` provides a mock with real ECDSA;
  tests that need the actual Keychain must be run manually

## Build and test commands

```bash
make build          # compile binary
make test           # go test -v -race -count=1 ./...
make install        # build + codesign + install to /usr/local/bin
make test-cover     # run tests + generate coverage.html
make clean          # remove build artifacts
```

Quick run:
```bash
./touchid-agent -l /tmp/.touchid-agent.sock
export SSH_AUTH_SOCK=/tmp/.touchid-agent.sock
```

## Architecture

```
main.go                  CLI + daemon (flag parsing, socket lifecycle)
agent.go                 SSH agent protocol (golang.org/x/crypto/ssh/agent)
hook.go                  Post-create hook execution
keystore.go              KeyStore interface — testability boundary
secureenclave_darwin.go  Go/CGo bridge to Security.framework
secureenclave.m          Obj-C: key generation, signing, listing, deletion
notify_darwin.go         Touch ID reminder notification
contrib/hooks/           Example provisioning hooks (GitHub, etc.)
contrib/completions/     Shell completions (bash, zsh)
contrib/plist/           launchd service template
```

See `docs/architecture.md` for design principles and `docs/decisions.md` for
a log of architecture and strategy decisions.

## Testing

- All tests use the race detector: `make test`
- `keystore_mock_test.go` provides a mock `KeyStore` with real ECDSA signing (no Keychain needed)
- `agent_integration_test.go` covers the full agent-socket path with the mock store
- When adding tests that require the real Keychain/Secure Enclave, document the manual steps

## Shell Completions

When adding, removing, or renaming CLI flags in `main.go`, update the shell
completion scripts to stay in sync:

- `contrib/completions/touchid-agent.bash` — update `_touchid_agent_flags` and
  the `case` statement for flags that take values.
- `contrib/completions/touchid-agent.zsh` — update the `_arguments` list.

Flags that accept a value (e.g. `-create NAME`) need special handling in both
scripts: bash needs a `case` entry to suppress file completion, zsh needs a
`:description:` suffix on the argument spec.
