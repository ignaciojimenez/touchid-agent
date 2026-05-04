# Architecture

```
main.go                  CLI, daemon lifecycle, post-create hooks
agent.go                 SSH agent protocol, notifications
keystore_fs.go           KeyStore interface + filesystem implementation
secureenclave.swift      CryptoKit bridge: SE P-256 sign/generate
secureenclave_bridge.h   C header for the cgo / Swift boundary
secureenclave_darwin.go  Go side of the cgo bridge, Key type
contrib/hooks/           Example provisioning hooks (GitHub, etc.)
contrib/completions/     Shell completions (bash, zsh)
contrib/plist/           launchd service template
```

## Storage layout

```
~/.touchid-agent/                    (mode 0700)
└── keys/                            (mode 0700)
    ├── ssh.json                     (mode 0600)
    ├── git.json
    └── ...
```

Each `<label>.json` file embeds a SEP-wrapped `dataRepresentation` blob
plus metadata and a cached uncompressed EC public point so `-list` does
not have to round-trip through the SEP.

## Why CryptoKit

CryptoKit's `SecureEnclave.P256.Signing.PrivateKey` and the lower-level
Security.framework `SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave`
path both produce keys in the same Secure Enclave hardware with the same
non-extractability and biometry guarantees. The difference is that the
Security.framework path inserts the resulting key into the data-protection
keychain, which on macOS 14+ requires the `keychain-access-groups`
entitlement, which in turn requires an embedded provisioning profile. A
flat Mach-O CLI binary has no supported location for a provisioning
profile (only `.app` bundles do), so AMFI rejects flat binaries that
claim that entitlement. CryptoKit talks to the SEP directly without
involving the keychain, which is what lets us ship a flat
Developer-ID-signed Mach-O with no entitlements at all.

The cost is that persistence becomes the agent's responsibility -- keys
live as files in `~/.touchid-agent/keys/` instead of in the macOS
keychain. The same architectural choice is made by
[`age-plugin-se`](https://github.com/remko/age-plugin-se).

## Design principles

| Principle | Implementation |
|-----------|---------------|
| Keys never leave hardware | SE-backed keys are generated in and used by the SEP (ECDSA P-256); the on-disk blob is SEP-wrapped and unusable elsewhere. |
| Per-operation authentication | Touch ID required for each signing request when `.biometryAny` is set on key creation. |
| Drop-in replacement | Standard SSH agent protocol. Set `SSH_AUTH_SOCK` and go. |
| Multiple named keys | One key per purpose (e.g., `ssh` for auth, `git` for signing). |
| No secrets in memory | All signing delegates to CryptoKit / SEP; the agent never sees the private key. |
| Creation self-test | `-create` always signs and verifies a synthetic digest before reporting success, forcing the Touch ID prompt at create-time and proving the access control is correctly applied. |
| macOS only | By design. The Secure Enclave is Apple hardware. |
