# TODO

Tracking against two goals:

1. **Real drop-in replacement for yubikey-agent.** A user comfortable
   with yubikey-agent should be able to switch in minutes — same
   `brew install`, same setup ergonomics, same SSH plumbing.
2. **Close to ready for a Homebrew formula.** Tagged release, universal
   binary, notarized, with a release script that produces a bottle-able
   tarball.

## Done

- [x] CryptoKit migration: flat Mach-O Developer-ID-signed binary with no
      entitlements and no provisioning profile reaches the SEP via
      `SecureEnclave.P256.Signing.PrivateKey` (spec at
      [docs/cryptokit-migration.md](cryptokit-migration.md)).
- [x] Software keys (`-software -no-touch`) via the same Swift bridge,
      working on ad-hoc-signed builds.
- [x] Filesystem-backed `KeyStore` at `~/.touchid-agent/keys/<label>.json`
      with cached pubkey for prompt-free `-list`.
- [x] Creation self-test that signs and verifies a synthetic digest before
      reporting success (forces Touch ID at create time and proves the
      access control end-to-end).
- [x] CLI rule: `-software` requires `-no-touch` (the
      software-key-with-Touch-ID matrix cell is gone).
- [x] End-to-end real-world SSH session against unmodified production
      sshd validated (Phase 5).
- [x] Test suite green with race detector; mock store for unit tests.
- [x] Docs refreshed: README, THREAT_MODEL, architecture, building,
      migration, CONTRIBUTING.

## 1. Drop-in replacement gaps

### 1.1 Brew-installable

Until `brew install touchid-agent` works, the migration story for a
yubikey-agent user is "clone the repo and run make" — that is not a
drop-in feel. This is the single biggest UX gap. Resolved by §2 below.

### 1.2 launchd plist usability ✓

Plist template now uses `__BINARY__` and `__HOME__` placeholders. A
`make install-launchd` target generates the plist with correct paths.
Socket moved to `~/Library/Caches/touchid-agent/agent.sock` (per-user,
matching yubikey-agent convention). See `docs/launchd.md`.

### 1.3 Side-by-side migration map in `docs/migration.md` ✓

Command-by-command mapping table added covering install, create, list,
delete, start/stop, socket path, and SSH config. Includes the hard-stop
note about non-migratable keys.

## 2. Homebrew readiness

### 2.1 Universal binary ✓

`make universal` target added. Builds `libsecureenclave.a` for both
arm64 and x86_64 via `swiftc`, lipo-merges them, builds Go for both
`GOARCH` values, and produces a single fat Mach-O. `make build` remains
host-arch for the fast dev loop.

### 2.2 Notarization

The binary is now notarization-ready (hardened runtime + secure
timestamp) but we don't notarize it. For Homebrew distribution
Gatekeeper will not block us (Homebrew sets the quarantine bit only on
downloaded archives), but notarization is what lets users trust the
binary outside the brew install path (manually downloaded releases).

**Action:** add a `make notarize` target wrapping `xcrun notarytool
submit` against an App Store Connect API key stored in the keychain
profile. Document the prerequisite Apple Developer credentials.

### 2.3 Release script

Tie the previous two together: a script that takes a version tag,
builds the universal binary, signs, notarizes, packages as
`touchid-agent-vX.Y.Z-darwin-universal.tar.gz`, computes SHA-256, and
writes a release notes draft. GitHub Actions on tag push is the natural
trigger.

### 2.4 First tagged release (v0.1.0)

Nothing is tagged yet. A semver tag is the prerequisite for a brew
formula; the formula's `url` points at a specific tag's tarball.

### 2.5 Homebrew formula

Needs a separate tap repo (e.g. `ignaciojimenez/homebrew-touchid-agent`)
or submission to homebrew-core. Per yubikey-agent's pattern:

- `depends_on macos: ">= big_sur"`
- `depends_on "go" => :build`, `xcode: :build` (for swiftc)
- Or skip building from source entirely and ship a notarized bottle —
  cleaner for users.
- `caveats` block covering the SSH config setup and the launchd
  load/unload commands.

**Action:** decision call — bottle (notarized binary, no Go/Xcode for
end users) vs. source build (more transparent, requires toolchain).
Bottle is better for the drop-in goal. Punt to once §2.1–§2.4 are
done.

## 3. Migration loose ends

### 3.3 Update shell completions for `-software` rule ✓

Bash completion has a comment noting `-software` requires `-no-touch`.
Zsh description updated to `(requires -no-touch)`. Both also updated
for new `-version` flag.

### 3.4 Fix self-test error wording on recoverable failures ✓

`classifySignError()` maps LAError codes (-2 userCancel, -4
passcodeNotSet, -6 biometryNotAvailable, -7 biometryNotEnrolled, -8
biometryLockout) to actionable messages. The generic "likely a bug"
wording is removed. The same classifier is used in both the self-test
and agent sign paths. Covered by `TestClassifySignError`.

### 3.5 Decide on `-post-hook` semantics ✓

Option B chosen: `-post-hook` takes a path to an executable, not a
shell expression. `docs/hooks.md`, CLI usage text, and flag description
updated to document this explicitly.

## 4. Polish & deferred

These do not block the two main goals. Capture and revisit.

- [x] Error classification beyond §3.4 — `classifySignError()` used in
      both self-test and agent sign paths. Unknown errors still pass
      through verbatim.
- [x] `docs/git-signing.md` now includes the SSH allowed-signers file
      setup so `git log --show-signature` works locally.
- [ ] Optional `touchid-agent -migrate-keychain` tool that reads the
      pre-CryptoKit keychain items via legacy code and writes JSON
      files. Spec §10.4 punted on this; users were told to re-create.
      Reconsider only if anyone actually upgrades from a pre-migration
      install.
- [x] `touchid-agent -version` flag added (prints version to stdout
      and exits).
- [ ] launchd: investigate `Sockets` key for socket-activation rather
      than `RunAtLoad + KeepAlive`. Lower idle footprint, faster
      first-connection latency.
