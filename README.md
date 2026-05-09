# touchid-agent

touchid-agent is a seamless ssh-agent for the macOS Secure Enclave.

* **No hardware to carry.** Every modern Mac has a Secure Enclave. No USB tokens, no dongles, no "I forgot my YubiKey."
* **Multiple named keys.** Create as many keys as you need, each with its own label and Touch ID policy. Separate keys by environment, service, or trust level.
* **Touch ID per signature.** Biometric confirmation configurable per key: require Touch ID for sensitive operations, skip it where automation matters.
* **Drop-in replacement.** Standard SSH agent protocol. Set `SSH_AUTH_SOCK` and go. Compatible with all SSH servers and services.
* **Indestructible keys.** Generated inside the Secure Enclave, never exportable. There is no file to steal.

Drop-in replacement for [yubikey-agent](https://github.com/FiloSottile/yubikey-agent) -- same protocol, same key types (ECDSA P-256), but with support for multiple independently configured keys (yubikey-agent is limited to a single key).

## Installation

```bash
brew install ignaciojimenez/tap/touchid-agent
```

The formula ships a pre-built, Developer-ID-signed and notarized
universal binary — no Xcode or Go toolchain required.

### Building from source

Only needed if you want to hack on the code itself. See
[CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites and build details.

```bash
make install CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
```

> **Note:** ad-hoc-signed builds (the default `make install`) cannot access
> the Secure Enclave. A Developer ID is required for production use.

## Usage

```bash
# Create a key with Touch ID required per signature
touchid-agent -create ssh

# Create another key without Touch ID (for automated operations)
touchid-agent -create git -no-touch

# Labels are arbitrary -- use whatever fits your workflow
touchid-agent -create ssh-prod
touchid-agent -create ssh-staging -no-touch

# Run the agent
touchid-agent -l /tmp/.touchid-agent.sock

# Point SSH at the agent
export SSH_AUTH_SOCK="/tmp/.touchid-agent.sock"
ssh-add -L
```

Manage keys:

```bash
touchid-agent -list
touchid-agent -delete ssh
touchid-agent -delete-all
```

## Documentation

| Topic | Link |
|-------|------|
| Git commit signing | [docs/git-signing.md](docs/git-signing.md) |
| Post-create hooks | [docs/hooks.md](docs/hooks.md) |
| Running as a launchd service | [docs/launchd.md](docs/launchd.md) |
| Migrating from yubikey-agent | [docs/migration.md](docs/migration.md) |
| Operational runbook | [docs/runbook.md](docs/runbook.md) |
| Building and signing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Release process | [docs/release.md](docs/release.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Threat model | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |

## Security

Private keys are generated inside the Secure Enclave and cannot be exported.
The agent process never holds key material -- all signing is delegated to
CryptoKit, which talks to the SEP directly. Keys are persisted as opaque
SEP-wrapped blobs at `~/.touchid-agent/keys/<label>.json` (mode 0600).

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full analysis.

## License

[MIT](https://github.com/ignaciojimenez/touchid-agent/blob/main/LICENSE)
