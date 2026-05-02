# Threat Model

touchid-agent is an SSH agent for macOS that stores ECDSA P-256 keys in the
Secure Enclave (or Keychain) with optional per-key Touch ID enforcement.

This document describes the threats it resists, partially resists, and
explicitly does not resist.

## Architecture

```
SSH client → Unix socket (0600) → Agent → Keychain/SE → Sign
```

Private keys are created in and never leave the Secure Enclave hardware. The
agent holds no key material in process memory; all signing operations are
delegated to Security.framework, which communicates with the SEP.

## Threats

### Malware on Host (user-level)

| Control | Status |
|---------|--------|
| Private key extraction | **Mitigated.** Keys are non-exportable from the SE. |
| Silent signing (with Touch ID key) | **Mitigated.** Each sign requires biometric confirmation. |
| Silent signing (no-touch key) | **Not mitigated.** Any process running as the user can connect to the agent socket and issue signing requests. |
| Agent socket impersonation | **Partially mitigated.** Socket is created with 0600 permissions. Malware could manipulate SSH_AUTH_SOCK. |

### Root Compromise

| Control | Status |
|---------|--------|
| Key material extraction | **Mitigated.** SE is a separate hardware processor; root cannot extract keys. |
| Socket access | **Not mitigated.** Root can read/write any Unix socket. |
| Binary replacement | **Not mitigated.** Root can replace the agent binary. |
| Touch ID bypass | **Partially mitigated.** Root may be able to suppress or fake biometric prompts in some configurations. |

### Key Theft via Network

**Fully mitigated.** On hardware backends, the private key physically cannot
leave the Secure Enclave. There is no export mechanism, no file to steal, and
no memory to dump that contains key material. This is the primary advantage
over file-based SSH keys.

### Agent Socket Abuse

| Control | Details |
|---------|---------|
| Socket permissions | Created with mode 0600 (owner-only). |
| Socket directory | Created with mode 0700. |
| Stale socket detection | Agent checks for a running instance before replacing the socket. |
| Connection timeouts | Idle connections are closed after 10 minutes to prevent FD exhaustion. |

### Denial of Service

| Vector | Mitigation |
|--------|------------|
| Connection flood | Temporary accept errors are handled with backoff; non-temporary errors are fatal (crash-and-restart via launchd). |
| Hung client holding mutex | Connection timeout (10 min) prevents indefinite lock holding. |
| Socket replacement | Stale socket detection prevents silent replacement of a running agent. |

### osascript Injection

Touch ID notification messages are displayed via osascript. Input is sanitized:
backslashes and double quotes are escaped, backticks and `$()` are stripped.

### Key Label Collision

`-create` checks for existing keys with the same label before generating.
Labels are validated: no colons, no path separators, max 64 characters.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| Key non-exportability | Enforced by Secure Enclave hardware. |
| Per-operation biometric | Enforced by Security.framework access controls (`kSecAccessControlBiometryAny`). |
| Key isolation | Each key has a unique Keychain application tag. Keys are not shared across applications. |
| Socket security | Owner-only permissions (0600). |
| Signal handling | SIGTERM/SIGINT clean up the socket file. SIGHUP is handled without termination. |

## Software-Backed Keys

Keys created with `-software` are stored in the macOS Keychain but not in the
Secure Enclave. These keys are:

- Protected by Keychain access controls (user login required).
- Not hardware-isolated: they exist in Keychain's encrypted store and are
  theoretically extractable by a privileged process.
- Useful for development/testing on machines without Secure Enclave access
  or without a code signing identity.

Software-backed keys provide convenience, not hardware-grade security.

## Out of Scope

- **Physical attacks on the Secure Enclave.** We rely on Apple's hardware
  security guarantees.
- **Kernel exploits.** A kernel-level compromise can bypass all software
  protections.
- **SSH protocol weaknesses.** touchid-agent implements key management, not
  the SSH protocol.
- **Supply chain attacks on this binary.** Standard mitigation: code signing,
  reproducible builds.

## Design Decisions

### Why Security.framework, not CryptoKit

Both APIs access the same Secure Enclave hardware with identical cryptographic
guarantees. We chose Security.framework because:

1. **Language compatibility.** Go + CGo + Objective-C. CryptoKit requires Swift.
2. **Keychain integration.** System-managed persistence, listing, deletion, and
   access control. CryptoKit stores key handles as files, which lack Keychain's
   layered protections.
3. **Enterprise readiness.** Keychain items are MDM-manageable.
4. **Maturity.** Security.framework SE support has been stable since macOS 10.12.

The code signing requirement applies equally to both approaches. It is a
feature: it proves the binary is trusted.

### Why ECDSA P-256 Only

The Secure Enclave only supports NIST P-256. Ed25519 and RSA cannot be
generated in hardware. Existing file-based keys in `~/.ssh` continue to
work alongside touchid-agent keys.
