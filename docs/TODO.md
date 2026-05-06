# TODO

- Figure out how to document development flow for my own reference in the future
- Review documentation to make sure it's lean and only necessary docs remain
- Build most common use cases for hooks
- Perform an advanced attack and threat model assessment specially of the hook functionality

### 1.5 Subsequent releases

Fully automated. Push a tag and CI handles everything — build, sign,
notarize, publish the GitHub release, and update the Homebrew tap:

```bash
make test
git tag vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
```

End users get the update via `brew update && brew upgrade touchid-agent`.

### 1.6 Re-running a failed release

If the workflow fails partway and you fix the issue, you must delete
both the GitHub release draft (if any) and the tag, then re-tag:

```bash
gh release delete v0.1.0 --yes --cleanup-tag    # also deletes the tag
# fix the issue, push the fix to main, then:
git tag v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

`--cleanup-tag` is important — re-pushing a tag that already exists on
the remote requires `--force`, and force-pushing tags is banned by the
permissions in `release.yml`.



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
- ** First tagged release v0.1.2**
