# touchid-agent

An SSH agent for macOS that stores keys in the Secure Enclave with Touch ID
authentication. Drop-in replacement for
[yubikey-agent](https://github.com/FiloSottile/yubikey-agent) -- same agent
protocol, no USB hardware required.

## Why

Every modern Mac has a Secure Enclave -- a hardware security processor that
generates and stores cryptographic keys that never leave the chip. Touch ID
provides biometric confirmation per signing operation. Same security properties
as a YubiKey, zero hardware logistics.

## Requirements

- macOS 12+ (Monterey or later)
- Go 1.22+ (to build from source)
- Apple Developer ID (for Secure Enclave and Touch ID features; ad-hoc signing
  works for software-backed keys without Touch ID)

## Install

```bash
make install
```

Production builds require a Developer ID to embed keychain entitlements:

```bash
make install CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
```

| Feature | Ad-hoc (default) | Developer ID |
|---------|:----------------:|:------------:|
| Software key, no Touch ID | yes | yes |
| Software key, Touch ID | no | yes |
| Secure Enclave key | no | yes |

See [docs/building.md](docs/building.md) for build variables and details.

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
