# Threat Model

touchid-agent is an SSH agent for macOS that stores ECDSA P-256 keys in the
Secure Enclave with optional per-key Touch ID enforcement.

This document describes the threats it resists, partially resists, and
explicitly does not resist.

## Architecture

```
SSH client → Unix socket (0600) → Agent → CryptoKit → SEP → Sign
                                          ↑
                                ~/.touchid-agent/keys/<label>.json
                                (opaque SEP-wrapped blob + cached pubkey)
```

The private material is generated inside the SEP and never appears in
process memory. Persistence is a SEP-wrapped `dataRepresentation` blob
on disk that is unusable on any other device or by any other user;
signing reconstructs the key handle in the SEP from that blob, never the
key itself.

## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Unix socket ↔ Agent | User-owned socket (0600). Any same-UID process can connect. Peer credentials (PID, UID, binary path) are captured for audit. |
| Agent ↔ Secure Enclave | Key material never crosses this boundary in plaintext. CryptoKit talks to the SEP directly; the agent holds only opaque wrapped blobs. |
| Agent ↔ Filesystem | JSON keyfiles in `~/.touchid-agent/keys/` (0600 files, 0700 directory). Contains SEP-wrapped tokens, not raw key material. |
| Agent ↔ Post-create hook | User-supplied executable path invoked via `exec.Command` (no shell interpretation). Receives key metadata via environment variables; never receives private key material. |
| Agent ↔ osascript | Notification subprocess for Touch ID prompts and signing alerts. Input is sanitized against injection. |

## Threats

### Malware on Host (user-level)

| Control | Status |
|---------|--------|
| Private key extraction | **Mitigated.** The SEP-wrapped blob on disk is non-extractable; the actual private key never leaves SEP hardware. |
| Silent signing (Touch ID-gated key) | **Mitigated.** Each signing operation requires biometric confirmation enforced by the SEP. |
| Silent signing (no-touch key) | **Partially mitigated.** By default, a macOS notification is shown on every no-touch signing event. With `-peer-check`, only binaries in the allowlist (default: system and Homebrew `ssh`, `scp`, `sftp`) can trigger a signing request; unknown processes are rejected. With `-rate-limit`, signing frequency per key is capped (hard ceiling: 120/min). A sufficiently capable same-UID attacker who can inject into an allowed process or modify the launchd plist can still bypass these controls; Touch ID remains the only hardware-enforced guarantee. |
| Agent socket impersonation | **Partially mitigated.** Socket is 0600, directory 0700. Malware could manipulate `SSH_AUTH_SOCK`. |

### Root Compromise

| Control | Status |
|---------|--------|
| Key material extraction | **Mitigated.** The SEP is a separate hardware processor; root cannot extract keys, only request signatures (which on Touch-ID-gated keys still require biometry). |
| Socket access | **Not mitigated.** Root can read/write any Unix socket. |
| Binary replacement | **Not mitigated.** Root can replace the agent binary. |
| Touch ID bypass | **Partially mitigated.** Root may be able to suppress or fake biometric prompts in some configurations. |

### Key Theft via Network

**Fully mitigated.** The private key physically cannot leave the Secure
Enclave. There is no export mechanism, no file to steal, and no memory
to dump that contains key material.

### Agent Socket Abuse

| Control | Details |
|---------|---------|
| Socket permissions | Created with mode 0600 (owner-only). |
| Socket directory | Created with mode 0700. |
| Connection timeouts | Idle connections are closed after 10 minutes to prevent FD exhaustion. |
| Peer binary verification (`-peer-check`) | The binary path of the connecting process is resolved via `proc_pidpath(3)` and checked against an allowlist of known SSH clients. Unknown processes are rejected for no-touch key signing. Symlinks in the allowlist are resolved at check time so Homebrew Cellar paths match correctly. |
| Rate limiting (`-rate-limit N`) | Signing operations are limited per key per minute using a sliding window. The ceiling is hard-coded at 120/min and cannot be overridden by configuration. |
| Default signing audit | When no `-audit-log` path is provided, signing events are emitted as JSON to stderr so they appear in the launchd log. |

### Denial of Service

| Vector | Mitigation |
|--------|------------|
| Connection flood | Temporary accept errors are handled with backoff; non-temporary errors are fatal (crash-and-restart via launchd). |
| Hung client holding mutex | Connection timeout (10 min) prevents indefinite lock holding. |

### Input Validation

- **osascript injection**: Notification messages are sanitized —
  backslashes and double quotes are escaped; backticks and `$()` are
  stripped.
- **Key labels**: Validated to forbid colons, path separators, and
  strings longer than 64 characters. `loadKeyfile` rejects files whose
  JSON-claimed label does not match the on-disk filename.
- **Post-create hooks**: Invoked via `exec.Command` (single argument,
  no shell). The hook receives metadata through environment variables
  (`TOUCHID_AGENT_LABEL`, `TOUCHID_AGENT_PUBKEY`, etc.) but never
  private key material.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| Key non-exportability | Enforced by Secure Enclave hardware. |
| Per-operation biometric | Enforced by `SecAccessControlCreateFlags` `.privateKeyUsage \| .biometryAny` evaluated by the SEP at every `signature(for:)` call. |
| Key isolation | Each key is its own file under `~/.touchid-agent/keys/`. There is no cross-process keychain item to enumerate or share. |
| Keystore directory security | `~/.touchid-agent/keys/` is created and enforced at mode 0700; the agent refuses to start if `chmod` fails, preventing operation with insecure key storage. |
| Socket security | Owner-only permissions (0600), parent directory 0700. |
| Signal handling | SIGTERM/SIGINT clean up the socket file. SIGHUP is handled without termination. |
| Signing audit | Every signing operation is logged (JSON-lines) — to the file specified by `-audit-log`, or to stderr by default. Each record includes timestamp, key label, success/failure, peer PID, UID, and binary path. |
| Caller verification | When `-peer-check` is enabled, the connecting process binary is validated against an allowlist before no-touch keys are used. |
| Rate limiting | When `-rate-limit` is set, per-key signing frequency is bounded by a sliding window with a hard-coded ceiling of 120/min. |

## Code Signing

Production builds are signed with Developer ID, hardened runtime
(`--options runtime`), and a secure timestamp (`--timestamp`). The binary
embeds **no entitlements** and contains no provisioning profile.

CryptoKit's `SecureEnclave.P256.Signing.PrivateKey` API bypasses the
data-protection keychain entirely, which allows the binary to ship as a
flat Mach-O without entitlements or a provisioning profile. See
[Design Decisions](#design-decisions) for the full rationale.

## Attestation

There is **no cryptographic attestation** that a touchid-agent public
key was generated inside the Secure Enclave. A remote verifier sees only
an `ecdsa-sha2-nistp256` public key and cannot distinguish it from a
software-generated key. This is a platform limitation: Apple does not
expose an attestation chain for SE keys on macOS (iOS has
`SecKeyCreateAttestation`, but it is unavailable on macOS).

### What this means in practice

| Trust assumption | Implication |
|---|---|
| Managed endpoint | MDM-attested device posture already trusts the endpoint; SE attestation would be redundant. |
| Unmanaged endpoint | A remote verifier cannot confirm hardware backing. Compromise resistance depends on the user account and binary integrity. |
| User is the threat | The SEP prevents key exfiltration even without attestation. The user can register a different key, but cannot leak the SE one. |

### Recommended mitigations for corporate deployment

1. **Pair touchid-agent with device posture checks.** Enforce SSH access
   only from MDM-enrolled, encrypted, up-to-date Macs. Cloudflare
   Access, Tailscale ACLs, or an SSH CA that requires a short-lived
   posture-attested certificate are all reasonable patterns.
2. **Pin the binary.** Distribute through a controlled channel (internal
   Homebrew tap, MDM-pushed package). Verify the notarization signature:
   `codesign -dv --verbose=4 /path/to/touchid-agent`. The expected
   `Authority=` chain ends in `Apple Root CA`.
3. **Audit log signing events** and ship the log to a SIEM. Signing
   events are emitted to stderr by default (visible in `log show` and
   the launchd journal); for structured retention use `-audit-log PATH`.
   Each record includes the peer process path for attribution.
4. **Enable caller verification.** Add `-peer-check` to the launchd plist
   arguments. No-touch key signing is then restricted to binaries in the
   default allowlist (`/usr/bin/ssh`, `/opt/homebrew/bin/ssh`, etc.).
   Add organisation-specific SSH clients via `-allowed-callers PATH`.
5. **Enable rate limiting.** Add `-rate-limit 60` (or lower) for keys
   that are not expected to sign at high frequency. Use Touch ID-gated
   keys for anything where the rate limit alone is insufficient.
6. **Treat each key as scoped.** Use distinct labels for different
   privilege boundaries (`ssh-prod`, `git-signing`, `ssh-staging`) so a
   compromised endpoint can be narrowed down by which key was used.

### What attestation would buy you

If Apple shipped SE attestation on macOS, a verifier could prove that a
specific public key originated from a SEP and is biometry-gated, without
trusting the agent binary. Until then, the trust anchor is the endpoint.

## Out of Scope

- **Physical attacks on the Secure Enclave.** We rely on Apple's
  hardware security guarantees.
- **Kernel exploits.** A kernel-level compromise can bypass all software
  protections.
- **SSH protocol weaknesses.** touchid-agent implements key management,
  not the SSH protocol.
- **Supply chain attacks on this binary.** Standard mitigation: code
  signing, reproducible builds, Homebrew distribution of notarized
  binaries.

## Design Decisions

### Why CryptoKit, not Security.framework

Both APIs access the same Secure Enclave hardware with identical
cryptographic guarantees. We chose CryptoKit because:

1. **Distribution as a flat Mach-O.** `SecKeyCreateRandomKey` with
   `kSecAttrTokenIDSecureEnclave` routes through the data-protection
   keychain, which AMFI gates behind `keychain-access-groups`. That
   entitlement requires an embedded provisioning profile, and a flat
   Mach-O has nowhere to embed one. CryptoKit bypasses the keychain.
2. **Same security guarantees.** Key non-extractability and biometry
   enforcement are properties of the hardware and `SecAccessControl`
   flags, not the framework wrapper.
3. **Simpler trust surface.** No entitlements means fewer trust
   assertions for reviewers and administrators to evaluate.

The cost is that persistence is the agent's responsibility (we manage
`~/.touchid-agent/keys/` instead of relying on the keychain). This is a
deliberate trade-off for distributability.

### Why ECDSA P-256 Only

The Secure Enclave only supports NIST P-256. Ed25519 and RSA cannot be
generated in hardware. Existing file-based keys in `~/.ssh` continue to
work alongside touchid-agent keys via separate SSH agent sockets.
