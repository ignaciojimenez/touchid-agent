# touchid-agent

touchid-agent is a seamless ssh-agent for the macOS Secure Enclave.

* **No hardware to carry.** Every modern Mac has a Secure Enclave. No USB tokens, no dongles, no "I forgot my YubiKey."
* **Touch ID per signature.** Biometric confirmation for every SSH or git signing operation, configurable per key.
* **Drop-in replacement.** Standard SSH agent protocol. Set `SSH_AUTH_SOCK` and go. Compatible with all SSH servers and services.
* **Indestructible keys.** Generated inside the Secure Enclave, never exportable. There is no file to steal.

Drop-in replacement for [yubikey-agent](https://github.com/FiloSottile/yubikey-agent) -- same protocol, same key types (ECDSA P-256), same two-key model.

## Installation

```bash
make install
```

For Secure Enclave and Touch ID features, sign with a Developer ID:

```bash
make install CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
```

| Feature | Ad-hoc (default) | Developer ID |
|---------|:----------------:|:------------:|
| Software key, no Touch ID | yes | yes |
| Software key, Touch ID | no | yes |
| Secure Enclave key | no | yes |

## Quick start

```bash
# Create a key (Touch ID required per signature)
touchid-agent -create ssh

# Create a key without Touch ID (for automated signing)
touchid-agent -create git -no-touch

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
| Build variables and signing | [docs/building.md](docs/building.md) |
| Git commit signing | [docs/git-signing.md](docs/git-signing.md) |
| Post-create hooks | [docs/hooks.md](docs/hooks.md) |
| Running as a launchd service | [docs/launchd.md](docs/launchd.md) |
| Migrating from yubikey-agent | [docs/migration.md](docs/migration.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Threat model | [THREAT_MODEL.md](THREAT_MODEL.md) |

## Security

Private keys are generated inside the Secure Enclave and cannot be exported.
The agent process never holds key material -- all signing is delegated to
Security.framework. Software-backed keys (`-software`) are stored in the macOS
Keychain, protected by login credentials but not hardware-isolated.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full analysis.

## License

[MIT](LICENSE)
