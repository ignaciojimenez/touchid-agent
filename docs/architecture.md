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

CryptoKit bypasses the data-protection keychain, which lets us ship a
flat Developer-ID-signed Mach-O with no entitlements. The cost is that
persistence becomes the agent's responsibility (keys live as files in
`~/.touchid-agent/keys/`). See [THREAT_MODEL.md](THREAT_MODEL.md#why-cryptokit-not-securityframework)
for the full rationale.

## Design principles

| Principle | Implementation |
|-----------|---------------|
| Keys never leave hardware | SE-backed keys are generated in and used by the SEP (ECDSA P-256); the on-disk blob is SEP-wrapped and unusable elsewhere. |
| Per-operation authentication | Touch ID required for each signing request when `.biometryAny` is set on key creation. |
| Drop-in replacement | Standard SSH agent protocol. Set `SSH_AUTH_SOCK` and go. |
| Multiple named keys | Create as many keys as needed with arbitrary labels (e.g., `ssh-prod`, `ssh-staging`, `git-signing`). Each key has its own Touch ID policy. |
| No secrets in memory | All signing delegates to CryptoKit / SEP; the agent never sees the private key. |
| Creation self-test | `-create` always signs and verifies a synthetic digest before reporting success, forcing the Touch ID prompt at create-time and proving the access control is correctly applied. |
| macOS only | By design. The Secure Enclave is Apple hardware. |
