# touchid-agent

touchid-agent is a seamless ssh-agent for the macOS Secure Enclave.

* **No hardware to carry.** Every modern Mac has a Secure Enclave. No USB tokens, no dongles, no "I forgot my YubiKey."
* **Multiple named keys.** Create as many keys as you need, each with its own label and Touch ID policy. Separate keys by environment, service, or trust level.
* **Touch ID per signature.** Biometric confirmation configurable per key: require Touch ID for sensitive operations, skip it where automation matters.
* **Drop-in yubikey-agent replacement.** Standard SSH agent protocol. Set `SSH_AUTH_SOCK` and go. Compatible with all SSH servers and services.
* **No keys to lose.** Generated inside the Secure Enclave, never exportable. There is no file to steal.

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
# Install the launchd plist (socket activation: agent starts on demand,
# exits after 10m idle). Idempotent.
touchid-agent -install-plist

# Create a key with Touch ID required per signature
touchid-agent -create ssh

# Labels are arbitrary -- use whatever fits your workflow
touchid-agent -create ssh-prod
touchid-agent -create ssh-staging -no-touch

# Point SSH at the agent
export SSH_AUTH_SOCK="$HOME/Library/Caches/touchid-agent/agent.sock"
ssh-add -L
```

Manage keys:

```bash
touchid-agent -list
touchid-agent -delete ssh
touchid-agent -delete-all
```

## Documentation

For more detailed information on specific topics, please refer to the following documents:

| Topic | Link |
|-------|------|
| Running as a launchd service | [docs/launchd.md](docs/launchd.md) |
| Post-create hooks | [docs/hooks.md](docs/hooks.md) |
| Migrating from yubikey-agent | [docs/migration.md](docs/migration.md) |
| Operational runbook | [docs/runbook.md](docs/runbook.md) |
| Threat model | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Release process | [docs/release.md](docs/release.md) |
| Distribution roadmap | [docs/distribution-roadmap.md](docs/distribution-roadmap.md) |
| Building and signing | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Security

Private keys are generated inside the Secure Enclave and cannot be exported.
The agent process never holds key material -- all signing is delegated to
CryptoKit, which talks to the SEP directly. Keys are persisted as opaque
SEP-wrapped blobs at `~/.touchid-agent/keys/<label>.json` (mode 0600).

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full analysis.

## License

[MIT](https://github.com/ignaciojimenez/touchid-agent/blob/main/LICENSE)
