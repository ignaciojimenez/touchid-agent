# TODO

## 1. First tagged release

Everything required to cut `v0.1.0` is in place; the remaining work is
operational, not code:

1. Provision the GitHub Actions secrets listed in `docs/release.md`
   (Developer ID `.p12` base64, Apple ID + team + app-specific
   password, keychain password, sign identity CN).
2. `git tag -s v0.1.0 -m "v0.1.0" && git push origin v0.1.0`. The
   `Release` workflow handles build → sign → package → notarize →
   release.
3. Create the personal tap repo (`ignaciojimenez/homebrew-tap`) and
   copy `contrib/homebrew/touchid-agent.rb` into `Formula/` with the
   real version + SHA-256 from the published release.

## 2. Deferred

- [ ] launchd socket activation: investigate `Sockets` key instead of
      `RunAtLoad + KeepAlive`. Lower idle footprint, faster
      first-connection latency. Would change the socket lifecycle
      (launchd owns the socket fd, agent inherits it).
- [ ] Notarization stapling: not currently possible for flat Mach-O
      CLI binaries (stapler only supports `.app`/`.dmg`/`.pkg`). Could
      be revisited if Apple ships flat-binary stapling, or if the
      project ships a `.pkg` installer for managed deployments.
- [ ] Optional: submit to homebrew-core. Requires either a
      source-buildable formula (impossible: ad-hoc-signed binaries
      cannot reach the SEP) or a maintainer-shipped notarized bottle.
      Personal tap is simpler and correct for this use case.

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
- Shell completions updated for `-version`, `-audit-log`.
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
- **Release pipeline**: `make package`, `make notarize`, `make release`,
  `scripts/release-notes.sh`, GitHub Actions release workflow on tag
  push, `docs/release.md`.
- **Homebrew formula**: `contrib/homebrew/touchid-agent.rb` (binary
  distribution; ad-hoc signing cannot grant SE access, so source-build
  via Homebrew is fundamentally not possible).
- **Attestation trust model documented** (`docs/THREAT_MODEL.md`):
  Apple does not expose SE key attestation on macOS; documented what
  this means for managed/unmanaged endpoints and recommended
  mitigations.
- **Operational runbook** (`docs/runbook.md`): biometry lockout
  detection + recovery, break-glass `-no-touch` key guidance, LAError
  reference table, agent crash recovery.
- **Structured audit log**: `-audit-log PATH` flag emits JSON-lines
  records (`ts`, `event`, `label`, `success`, `error`, `peer_pid`,
  `peer_uid`) on each signing operation.
- **CI supply chain hardening**: pinned `macos-14` runner,
  `go mod verify`, `govulncheck@v1.1.4`, `permissions: read`,
  `make vuln` for local scans.
