# Migrating from yubikey-agent

touchid-agent is a protocol-compatible replacement. Both agents can coexist
during the transition -- they use different sockets.

## Steps

1. Install touchid-agent and create keys alongside the running yubikey-agent.
2. Register the new public keys (`~/.ssh/touchid-agent-*.pub`) on all remote
   services where YubiKey keys are registered.
3. Stop yubikey-agent, start touchid-agent, update `SSH_AUTH_SOCK`.
4. Verify everything works, then revoke old YubiKey public keys.

## Comparison

| | yubikey-agent | touchid-agent |
|---|---|---|
| Hardware | USB YubiKey (PIV applet) | Mac Secure Enclave |
| Key creation | `yubikey-agent -setup` (single key) | `touchid-agent -create NAME` (multiple) |
| Authentication | PIN (once per session) + touch | Touch ID (per operation) or no-touch |
| Key portability | Carry YubiKey between machines | Device-bound, non-exportable |
| Software conflicts | Conflicts with gpg-agent, YubiKey Manager | None |
| Platform | macOS, Linux, FreeBSD | macOS only |
| Algorithm | ECDSA P-256 or RSA | ECDSA P-256 |
