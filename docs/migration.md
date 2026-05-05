# Migration

## Upgrading from pre-CryptoKit versions of touchid-agent

Earlier builds of touchid-agent stored keys in the macOS Keychain via
Security.framework. The current build stores keys as JSON files at
`~/.touchid-agent/keys/<label>.json` and uses CryptoKit to talk to the
Secure Enclave directly. The two storage backends use different SE token
formats and **cannot be transferred** — this is a one-time re-creation.

Steps:

1. While the old binary is still installed, list the keys you want to
   keep: `/usr/local/bin/touchid-agent -list`. Note the labels.
2. Install the new build: `brew install ignaciojimenez/tap/touchid-agent`
   (or `make install CODESIGN_IDENTITY="Developer ID Application: ..."` if building from source).
3. Re-create each key: `touchid-agent -create LABEL`. You will get a
   new public key for every label; update any `~/.ssh/authorized_keys`,
   GitHub / GitLab / Bitbucket SSH key entries, code-signing
   configurations, etc.
4. Optional: while the old binary is still around, delete the orphaned
   keychain items with `/usr/local/bin/touchid-agent.old -delete-all`
   (or remove them through Keychain Access). Once the old binary is
   gone, the orphaned items are harmless but uncleaned.

## Migrating from yubikey-agent

touchid-agent is a protocol-compatible replacement. Both agents can
coexist during the transition — they use different sockets.

Steps:

1. Install touchid-agent and create keys alongside the running
   yubikey-agent.
2. Register the new public keys (`~/.ssh/touchid-agent-*.pub`) on all
   remote services where YubiKey keys are registered.
3. Stop yubikey-agent, start touchid-agent, update `SSH_AUTH_SOCK`.
4. Verify everything works, then revoke the old YubiKey public keys.

### Command-by-command mapping

| Task | yubikey-agent | touchid-agent |
|------|---------------|---------------|
| Install | `brew install yubikey-agent` | `brew install ignaciojimenez/tap/touchid-agent` |
| Create key | `yubikey-agent -setup` (single key) | `touchid-agent -create ssh` |
| Create signing key | (not supported, single key only) | `touchid-agent -create git -no-touch` |
| List keys | n/a (one key, always loaded) | `touchid-agent -list` |
| Delete key | `ykman piv reset` | `touchid-agent -delete NAME` |
| Delete all keys | `ykman piv reset` | `touchid-agent -delete-all` |
| Start agent | `brew services start yubikey-agent` | `launchctl load ~/Library/LaunchAgents/touchid-agent.plist` |
| Stop agent | `brew services stop yubikey-agent` | `launchctl unload ~/Library/LaunchAgents/touchid-agent.plist` |
| Socket path | `~/Library/Caches/yubikey-agent/yubikey-agent.sock` | `~/Library/Caches/touchid-agent/agent.sock` |
| SSH config | `IdentityAgent ~/Library/Caches/yubikey-agent/yubikey-agent.sock` | `IdentityAgent ~/Library/Caches/touchid-agent/agent.sock` |

**Important:** YubiKey keys cannot be migrated to touchid-agent. The
keys are generated inside different hardware (PIV applet vs. Secure
Enclave) and are non-exportable by design. You must create new keys
with touchid-agent and register the new public keys on every remote
host, GitHub/GitLab account, and signing configuration.

### Comparison

| | yubikey-agent | touchid-agent |
|---|---|---|
| Hardware | USB YubiKey (PIV applet) | Mac Secure Enclave |
| Key creation | `yubikey-agent -setup` (single key) | `touchid-agent -create NAME` (multiple) |
| Authentication | PIN (once per session) + touch | Touch ID (per operation) or no-touch |
| Key portability | Carry YubiKey between machines | Device-bound, non-exportable |
| Software conflicts | Conflicts with gpg-agent, YubiKey Manager | None |
| Platform | macOS, Linux, FreeBSD | macOS only |
| Algorithm | ECDSA P-256 or RSA | ECDSA P-256 |
