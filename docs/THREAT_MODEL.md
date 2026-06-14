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

Every threat below is rated with the same vocabulary:

- **Mitigated** — addressed in hardware or by design; no practical residual.
- **Partial** — reduced, with a residual risk named in the notes.
- **Not mitigated** — out of scope or an accepted residual.
- **By design** — intentional behaviour, called out so it is not mistaken for a flaw.
- **Informational** — noted for completeness; not a risk in itself.

The controls referenced in the notes are catalogued in [Security Properties](#security-properties).

### Malware on host (same-UID, non-root)

| Threat | Status | Notes |
|--------|--------|-------|
| Private key extraction | Mitigated | The SEP-wrapped blob on disk is non-extractable; the key never leaves SEP hardware. |
| Silent signing — Touch-ID key | Mitigated | Every signing operation requires biometric confirmation enforced by the SEP. |
| Silent signing — no-touch key | Partial | A macOS notification fires on every signing event, and peer verification (below) is on by default. `-rate-limit` caps frequency. A same-UID attacker who injects into an allowed caller or edits the launchd plist can still bypass these; Touch ID is the only hardware-enforced guarantee. |
| Unauthorized local caller drives the agent | Partial | The socket is 0600 and peer verification gates callers by code-signing identity (Apple OS SSH binaries by default); `-require-hardened-callers` blocks injection into non-hardened callers. Same-UID injection into an allowed, hardened caller remains possible. |
| Socket impersonation via `SSH_AUTH_SOCK` | Partial | Socket is 0600, directory 0700; malware can still repoint `SSH_AUTH_SOCK` at its own socket. |

### Root compromise

| Threat | Status | Notes |
|--------|--------|-------|
| Key material extraction | Mitigated | The SEP is separate hardware; root can request signatures (touch-gated keys still need biometry) but cannot extract keys. |
| Socket access | Not mitigated | Root can read/write any Unix socket. |
| Binary replacement | Not mitigated | Root can replace the agent binary. |
| Touch ID bypass | Partial | Root may suppress or fake biometric prompts in some configurations. |

### Key theft over the network

| Threat | Status | Notes |
|--------|--------|-------|
| Remote key exfiltration | Mitigated | The private key cannot leave the Secure Enclave — no export mechanism, no file to steal, no memory to dump. |

### Denial of service

| Threat | Status | Notes |
|--------|--------|-------|
| Connection flood | Partial | Temporary accept errors back off; non-temporary errors crash-and-restart via launchd. |
| Hung client holding the key mutex | Mitigated | Idle connections are closed after 10 minutes. |

### Input validation

| Threat | Status | Notes |
|--------|--------|-------|
| osascript injection (notifications) | Mitigated | Messages are sanitized — backslashes and quotes escaped, backticks and `$()` stripped. |
| Malicious key label | Mitigated | `validateLabel` forbids colons, path separators, and labels over 64 chars; `loadKeyfile` rejects a label that does not match the on-disk filename. |
| Post-create hook input | By design | The hook is invoked via `exec.Command` (no shell), receives metadata via environment variables, and never receives key material. Detailed in [Post-Create Hook Attack Surface](#post-create-hook-attack-surface). |

## Post-Create Hook Attack Surface

The `-post-hook` flag allows an arbitrary executable to run after key
creation. The hook is invoked via `exec.Command` (no shell) and receives
key metadata through environment variables. It never receives private
key material. This section analyses the attack surface in detail.

### Execution model

```
cmdCreate() → validateLabel → store.Generate → selfTestKey → runPostHook
                                                                │
                                               exec.Command(hookPath)
                                               env: TOUCHID_AGENT_LABEL,
                                                    TOUCHID_AGENT_PUBKEY,
                                                    TOUCHID_AGENT_PUBKEY_FILE,
                                                    TOUCHID_AGENT_TOUCH_REQUIRED
                                               + full parent environment
```

The hook runs synchronously, with the same UID and privileges as the
agent process. It inherits stdout, stderr, and the full parent
environment.

### Threats and mitigations

| Threat | Status | Notes |
|--------|--------|-------|
| Shell injection via hook path | Mitigated | `exec.Command(hookCmd)` runs the binary directly; no shell interprets the path, so pipes, redirects, and inline shell syntax are inert. |
| Shell metacharacters in label | Partial | `validateLabel` rejects colons, path separators, and labels over 64 chars, but allows `$`, backticks, `()`, and semicolons. Harmless in the env-var transport (no shell expansion), but a hook that uses unquoted `$TOUCHID_AGENT_LABEL` in a shell expression could evaluate them. The `contrib/hooks/` examples are safe. |
| TOCTOU on hook binary | Not mitigated | Between `-post-hook PATH` being specified and the hook executing, a same-UID attacker with write access to the path could swap the binary — a narrow window. |
| No execution timeout | Not mitigated | A hanging hook blocks the create command indefinitely (no watchdog). This is a DoS against the operator, not privilege escalation. |
| Parent environment inheritance | Not mitigated | The hook inherits `os.Environ()`, which may include `DYLD_INSERT_LIBRARIES` etc. Typically neutralized under the hardened runtime, but a hook built without it could be affected. |
| Hook binary integrity | Not mitigated | The hook binary is not code-signing/hash verified. The trust model is that whoever supplies `-post-hook` is trusted — the same user with physical Touch ID access. |
| Non-atomic provisioning | By design | If the hook fails (e.g. a GitHub API error) the key exists locally but is not registered remotely; the user re-runs the hook or registers manually. See [docs/hooks.md](hooks.md). |
| Public key metadata in env | Informational | The hook receives the public key, label, and `.pub` path. Public keys are public by design; the path reveals `$HOME` structure, already known to same-UID processes. |

### Recommendations for hook authors

1. **Quote all variables.** Always use `"$TOUCHID_AGENT_LABEL"`, never
   bare `$TOUCHID_AGENT_LABEL`, in shell scripts.
2. **Use `set -euo pipefail`.** Both contrib hooks do this. Fail fast
   on errors, undefined variables, and broken pipes.
3. **Minimize scope.** A hook should do one thing (e.g., upload a key).
   Avoid chaining unrelated provisioning steps in a single hook.
4. **Do not embed secrets in hook scripts.** Use credential helpers
   (`gh auth`, `vault`, keychain) instead of hardcoded tokens.
5. **Verify the hook is not world-writable.** A hook in a shared
   location (e.g., `/tmp`) is trivially swappable.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| Key non-exportability | Enforced by Secure Enclave hardware. |
| Per-operation biometric | Enforced by `SecAccessControlCreateFlags` `.privateKeyUsage \| .biometryAny` evaluated by the SEP at every `signature(for:)` call. |
| Key isolation | Each key is its own file under `~/.touchid-agent/keys/`. There is no cross-process keychain item to enumerate or share. |
| Keystore directory security | `~/.touchid-agent/keys/` is created and enforced at mode 0700; the agent refuses to start if `chmod` fails, preventing operation with insecure key storage. |
| Socket security | Owner-only permissions (0600), parent directory 0700. |
| Signal handling | SIGTERM/SIGINT clean up the socket file. SIGHUP is handled without termination. |
| Signing audit | Every signing operation is logged (JSON-lines) — by default to `~/Library/Logs/touchid-agent-audit.log`, or to the path given by `-audit-log` (`-` = stderr). Each record includes timestamp, key label, success/failure, and the caller's PID/UID/path/code-signing identity. |
| Audit integrity | Records are hash-chained (`seq` + `prev` = SHA-256 of the previous record); `touchid-agent -verify-audit` detects any modification, reordering, or deletion of earlier records. This is tamper-**evident**, not tamper-proof — a same-UID attacker who can write the file can recompute the chain — so durable tamper-resistance comes from shipping the log to an append-only store off-host (the chain lets the receiver verify integrity on ingest). |
| Caller verification | On by default. The connecting process is resolved race-free from the socket's audit token (`LOCAL_PEERTOKEN`, not `proc_pidpath(PID)`) and matched by code-signing identity via `SecCode`. Default policy: a genuine Apple OS binary (`anchor apple`) whose Signing ID is one of `com.apple.{ssh,scp,sftp,ssh-keygen}` — unforgeable and stronger than a path check. Extend with `-allowed-callers` rules (`team-id:`/`signing-id:`, honored only for Apple-anchored signatures; `cdhash:`; or `path:` as an unsigned escape hatch, flagged at startup), ideally from a root-owned / Managed Preferences file. Opt out with `-no-peer-check`. |
| Hardened-runtime requirement | With `-require-hardened-callers`, an allowed caller must also run with the hardened runtime — a same-UID process cannot inject into it without root. |
| Per-key caller binding | `-create … -key-callers RULES` restricts a specific key to named callers, so a compromised allowed caller cannot drive every key. |
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
3. **Audit log signing events** and ship the log to a SIEM. Audit
   logging is on by default to `~/Library/Logs/touchid-agent-audit.log`;
   point it elsewhere with `-audit-log PATH` (or `-audit-log -` for
   stderr / the launchd journal). Each record includes the peer process
   path for attribution.
4. **Keep caller verification on.** Peer verification is enabled by
   default: signing is restricted to genuine Apple OS SSH binaries
   (`anchor apple` + `com.apple.{ssh,scp,sftp,ssh-keygen}`). Do **not**
   pass `-no-peer-check` on managed endpoints. Add organisation-specific
   clients via `-allowed-callers` rules — prefer `team-id:`/`signing-id:`
   (your own Developer ID is ideal and self-maintaining) over `path:`.
   **Deliver the rules file from a root-owned path or Managed Preferences**
   so the authorized caller cannot rewrite its own rule, and pin the flag
   fleet-wide through the `peer_check` Managed Preference. For an extra
   margin against the inject-into-an-allowed-process residual, add
   `-require-hardened-callers` (or the `require_hardened_callers` Managed
   Preference): a same-UID process cannot inject into a hardened-runtime
   caller without root. The Apple SSH tools are already hardened, so this
   does not break the default set.
5. **Enable rate limiting.** Add `-rate-limit 60` (or lower) for keys
   that are not expected to sign at high frequency. Use Touch ID-gated
   keys for anything where the rate limit alone is insufficient.
6. **Treat each key as scoped.** Use distinct labels for different
   privilege boundaries (`ssh-prod`, `git-signing`, `ssh-staging`) so a
   compromised endpoint can be narrowed down by which key was used. Bind a
   key to the specific caller(s) that should use it at creation time with
   `-key-callers` (e.g. `touchid-agent -create git-signing -key-callers
   signing-id:com.apple.ssh-keygen`); a caller must then satisfy both the
   global policy and the key's own rules, so a compromised allowed caller
   cannot drive *every* key.

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
