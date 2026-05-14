# touchid-agent

A seamless SSH agent for the macOS Secure Enclave. Drop-in replacement
for [yubikey-agent](https://github.com/FiloSottile/yubikey-agent) —
same protocol, same key shape (ECDSA P-256), no dongle.

* **No hardware to carry.** Every modern Mac has a Secure Enclave. Touch ID is the PIN.
* **Multiple named keys, per-key policy.** `ssh-prod` (touch-required), `ssh-ci` (no-touch, rate-limited), `git-signing` (touch). Lifts yubikey-agent's one-key limit.
* **Hardware non-exportability.** Keys are generated inside the SEP and cannot be extracted. No file to steal, no memory to dump.
* **Fleet-deployable.** Signed, notarized `.pkg` for MDM (Munki / Jamf / Kandji), with a configuration profile that pins agent flags via Managed Preferences.
* **Auditable.** Every signing event emits a JSON record with timestamp, key label, peer PID/UID, and binary path — built to ship to a SIEM.
* **Defense-in-depth.** Per-binary caller allowlist (`-peer-check`) gates no-touch keys to known SSH clients. Per-key rate limiting bounds blast radius if an allowed caller is compromised.
* **Hookable provisioning.** Post-create hooks register new keys with GitHub, an LDAP keyserver, or any HTTP endpoint — pubkey distribution without paste-and-pray. See [docs/hooks.md](docs/hooks.md).

## Installation

**Individual** — same shape as yubikey-agent, by design:

```bash
brew install ignaciojimenez/tap/touchid-agent
touchid-agent -install-plist
touchid-agent -create ssh
export SSH_AUTH_SOCK="$HOME/Library/Caches/touchid-agent/agent.sock"
```

**Fleet** — download the signed `.pkg` and `.mobileconfig` from the
latest [release](https://github.com/ignaciojimenez/touchid-agent/releases)
and push via your MDM. The bootstrap LaunchAgent activates the agent on
each user's first GUI login.

Both channels ship the same Developer ID-signed, notarized universal
binary. No Xcode or Go toolchain required.

## Usage

```bash
touchid-agent -create ssh                  # touch-required (default)
touchid-agent -create ssh-ci -no-touch     # no-touch, for automation
touchid-agent -list
touchid-agent -delete ssh
```

## Documentation

Full documentation lives in [`docs/`](docs/). Common entry points:

| Topic | Link |
|-------|------|
| Migrating from yubikey-agent | [docs/migration.md](docs/migration.md) |
| Fleet deployment (MDM, configuration profile, enrollment) | _planned_ |
| Threat model | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Post-create hooks | [docs/hooks.md](docs/hooks.md) |
| Operational runbook | [docs/runbook.md](docs/runbook.md) |
| Building from source | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Security

Private keys are generated inside the Secure Enclave and cannot be
exported. The agent process never holds key material — signing is
delegated to CryptoKit, which talks to the SEP directly. Keys persist
as opaque SEP-wrapped blobs at `~/.touchid-agent/keys/<label>.json`
(mode 0600), unusable on any other device or user.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full analysis.

## License

[MIT](https://github.com/ignaciojimenez/touchid-agent/blob/main/LICENSE)
