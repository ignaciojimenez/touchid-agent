# TODO

## 1. Homebrew distribution

### 1.1 Notarization

The binary is notarization-ready (hardened runtime + secure timestamp
via `make sign CODESIGN_IDENTITY="Developer ID Application: ..."`),
but we don't notarize yet. Homebrew won't be blocked by Gatekeeper,
but notarization is needed for users who download releases manually.

**Action:** add a `make notarize` target wrapping `xcrun notarytool
submit` against an App Store Connect API key stored in the keychain
profile. Document the prerequisite Apple Developer credentials.

### 1.2 Release script

Tie universal binary + signing + notarization together: a script that
takes a version tag, builds via `make universal`, signs, notarizes,
packages as `touchid-agent-vX.Y.Z-darwin-universal.tar.gz`, computes
SHA-256, and writes a release notes draft. GitHub Actions on tag push
is the natural trigger.

### 1.3 First tagged release (v0.1.0)

Nothing is tagged yet. A semver tag is the prerequisite for a brew
formula; the formula's `url` points at a specific tag's tarball.

### 1.4 Homebrew formula

Needs a separate tap repo (e.g. `ignaciojimenez/homebrew-touchid-agent`)
or submission to homebrew-core. Per yubikey-agent's pattern:

- `depends_on macos: ">= big_sur"`
- `depends_on "go" => :build`, `xcode: :build` (for swiftc)
- Or ship a notarized bottle -- no Go/Xcode needed for end users.
- `caveats` block covering SSH config setup and launchd commands.

**Decision needed:** bottle (notarized binary, better drop-in UX) vs.
source build (more transparent, requires toolchain). Bottle is better
for the drop-in goal. Punt to once 1.1--1.3 are done.

## 2. Corporate deployment readiness

Items identified during security review (comparing against
yubikey-agent and evaluating with STRIDE threat model). These should
be evaluated before production corporate rollout.

### 2.1 Key attestation

There is no way for a remote server to verify that a key was generated
inside the Secure Enclave vs. fabricated in software. YubiKeys have PIV
attestation certificates for this; Apple's SE does not expose an
attestation chain. This is a platform limitation, not a code bug.

In a zero-trust corporate environment this matters -- security depends
on trusting the endpoint, not cryptographic proof. Document the trust
model explicitly. Evaluate whether Apple's DeviceCheck / App Attest
APIs could provide a partial mitigation (they attest the app, not
individual keys).

### 2.2 Biometry lockout operational runbook

If Touch ID locks out (too many failed attempts), SE keys with
`requireTouch=true` are unusable until the user unlocks their Mac with
their password and recovers Touch ID. This is a security feature (no
downgrade to a weaker auth factor), but an operational risk -- a
locked-out engineer on an incident call cannot SSH anywhere.

`classifySignError()` already returns actionable guidance (LAError -8),
but ops teams need a documented runbook covering: how to detect
lockout, recovery steps, and whether `-no-touch` keys should exist as
break-glass alternatives.

### 2.3 Structured audit logging

Currently the agent only logs in debug mode (`-v`), and only to stderr.
There is no structured audit trail of signing operations. For SOC 2 and
corporate compliance, each sign event should log: key label, timestamp,
success/failure, and ideally the requesting process (via
`SO_PEERCRED` / `getpeereid` on the UNIX socket).

This should be a separate log stream (JSON to a file or syslog), not
mixed with debug output. Consider a `-audit-log PATH` flag.

### 2.4 Build pipeline supply chain

The `go.sum` integrity depends on the build pipeline. Verify that
CI/CD pins the Go toolchain version, validates `go.sum` against the
Go checksum database (`GONOSUMCHECK` is not set), and that the Swift
toolchain comes from Xcode (not a third-party source). Supply chain
attacks on Go modules are real -- `golang.org/x/crypto` is a
high-value target.

## 3. Deferred

- [ ] launchd socket activation: investigate `Sockets` key instead of
      `RunAtLoad + KeepAlive`. Lower idle footprint, faster
      first-connection latency. Would change the socket lifecycle
      (launchd owns the socket fd, agent inherits it).

---

## Done

- CryptoKit migration (SE via `SecureEnclave.P256.Signing.PrivateKey`).
- Filesystem-backed KeyStore with cached pubkey.
- Creation self-test (sign + verify before reporting success).
- End-to-end SSH session validated.
- Test suite green with race detector; mock store.
- Docs refreshed (README, THREAT_MODEL, architecture, CONTRIBUTING).
- launchd plist with `make install-launchd`, per-user socket path.
- Side-by-side migration map in `docs/migration.md`.
- Universal binary (`make universal`).
- Shell completions updated for `-version`.
- `classifySignError()` with actionable LAError messages.
- `-post-hook` takes executable path, not shell expression.
- `-version` flag.
- `docs/git-signing.md` with allowed-signers setup.
- Per-key mutex for concurrent signing on independent keys.
- Path traversal fix in `cmdDelete` (`validateLabel`).
- EC public key curve validation (`IsOnCurve`).
- Connection idle timeout (true per-read idle timer).
- Socket permission race fix (`umask(077)` before `net.Listen`).
- `golang.org/x/crypto` updated to v0.45.0.
- Codebase simplification: removed software backend, collapsed small
  files, renamed SEKey to Key.
