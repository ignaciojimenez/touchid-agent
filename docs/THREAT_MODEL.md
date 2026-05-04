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

## Threats

### Malware on Host (user-level)

| Control | Status |
|---------|--------|
| Private key extraction | **Mitigated.** The SEP-wrapped blob on disk is non-extractable; the actual private key never leaves SEP hardware. |
| Silent signing (Touch ID-gated key) | **Mitigated.** Each signing operation requires biometric confirmation enforced by the SEP. |
| Silent signing (no-touch key) | **Not mitigated.** Any process running as the user can connect to the agent socket and issue signing requests. |
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
to dump that contains key material. The blob persisted to disk is a
SEP-wrapped token that is useless without the same SEP on the same
device.

### Agent Socket Abuse

| Control | Details |
|---------|---------|
| Socket permissions | Created with mode 0600 (owner-only). |
| Socket directory | Created with mode 0700. |
| Connection timeouts | Idle connections are closed after 10 minutes to prevent FD exhaustion. |

### Denial of Service

| Vector | Mitigation |
|--------|------------|
| Connection flood | Temporary accept errors are handled with backoff; non-temporary errors are fatal (crash-and-restart via launchd). |
| Hung client holding mutex | Connection timeout (10 min) prevents indefinite lock holding. |

### osascript Injection

Touch ID notification messages are displayed via `osascript`. Input is
sanitized: backslashes and double quotes are escaped; backticks and
`$()` are stripped.

### Key Label Collision

`-create` checks for an existing keyfile with the same label before
generating; labels are validated to forbid colons, path separators, and
strings longer than 64 characters. Filenames are derived from the label,
and the `loadKeyfile` path rejects files whose JSON-claimed label does
not match the on-disk filename.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| Key non-exportability | Enforced by Secure Enclave hardware. |
| Per-operation biometric | Enforced by `SecAccessControlCreateFlags` `.privateKeyUsage \| .biometryAny` evaluated by the SEP at every `signature(for:)` call. |
| Key isolation | Each key is its own file under `~/.touchid-agent/keys/`. There is no cross-process keychain item to enumerate or share. |
| Socket security | Owner-only permissions (0600), parent directory 0700. |
| Signal handling | SIGTERM/SIGINT clean up the socket file. SIGHUP is handled without termination. |

## Code signing and runtime entitlements

Production builds are signed with Developer ID, hardened runtime
(`--options runtime`), and a secure timestamp (`--timestamp`). The binary
embeds **no entitlements** and contains no provisioning profile.

Secure Enclave access is obtained via Apple's **CryptoKit**
`SecureEnclave.P256.Signing.PrivateKey` API. Unlike the lower-level
`SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave` path, CryptoKit
talks to the SEP directly without inserting items into the
data-protection keychain. This is what lets the binary ship as a flat
Mach-O without a provisioning profile while still using the Secure
Enclave for hardware-backed keys (the Security.framework path requires
the `keychain-access-groups` entitlement, and AMFI on macOS 14+ refuses
to load a flat Mach-O that claims it without an embedded provisioning
profile, which only `.app` bundles can carry).

Security-relevant consequences of this approach:

- **Key non-extractability** is unchanged. The private key is generated
  inside the SEP and never exposed in plaintext. The
  `dataRepresentation` blob persisted to disk is a SEP-wrapped token
  that is unusable without the same SEP on the same device.
- **Touch ID enforcement** is unchanged. `SecAccessControl` flags
  `.privateKeyUsage | .biometryAny` are applied at key-creation time
  and enforced by the SEP at every signing operation.
- **Persistence security** is now the responsibility of the filesystem:
  key files are stored in `~/.touchid-agent/keys/` with directory mode
  0700 and file mode 0600. A user-level attacker who reads an SE keyfile
  gets only the wrapped blob, which they cannot unwrap on any device
  other than the originating Mac (and even on that Mac, signing requires
  Touch ID for biometry-gated keys).

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
cryptographic guarantees. We chose CryptoKit for these reasons:

1. **Distribution as a flat Mach-O.** `SecKeyCreateRandomKey` with
   `kSecAttrTokenIDSecureEnclave` routes through the data-protection
   keychain, which AMFI gates behind the `keychain-access-groups`
   entitlement. That entitlement requires an embedded provisioning
   profile, and a flat Mach-O has nowhere to embed one (only `.app`
   bundles do). CryptoKit's `SecureEnclave.P256.Signing.PrivateKey`
   bypasses the keychain entirely.
2. **Same security guarantees.** Both APIs use the same SEP. Key
   non-extractability and biometry enforcement are properties of the
   hardware and the `SecAccessControl` flags, not of the framework
   wrapper.
3. **Simpler trust surface.** No entitlements means fewer trust
   assertions for reviewers and MDM administrators to evaluate.

The cost is that persistence is now the agent's responsibility (we
manage `~/.touchid-agent/keys/` instead of relying on the keychain).
This is a deliberate trade-off for distributability; see also
`age-plugin-se`, which makes the same choice.

### Why ECDSA P-256 Only

The Secure Enclave only supports NIST P-256. Ed25519 and RSA cannot be
generated in hardware. Existing file-based keys in `~/.ssh` continue to
work alongside touchid-agent keys via separate SSH agent sockets.
