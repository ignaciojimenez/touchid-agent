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

### 1.2 launchd plist usability

`contrib/plist/touchid-agent.plist` currently hardcodes
`/usr/local/bin/touchid-agent` and `/Users/CHANGEME/...`. Two problems:

- Apple Silicon Homebrew installs at `/opt/homebrew/bin`, so the path is
  wrong out of the box for half of users.
- `CHANGEME` is a setup paper-cut. yubikey-agent's brew formula
  generates the plist post-install with the user's home and the brew
  prefix substituted in; we should do the same.

**Action:** decide whether to ship a sed-substitution `make
install-launchd` target or have the brew formula generate the plist.
Brew formula is the better long-term answer; keep the static plist as a
manual-install reference. While we're here, switch the socket path
default from `/tmp/.touchid-agent.sock` to
`$HOME/Library/Containers/touchid-agent/Data/io.touchid-agent.sock` (or
similar per-user location), matching yubikey-agent's convention.

### 1.3 Side-by-side migration map in `docs/migration.md`

The doc currently explains the *what*. Add a command-by-command table:

| yubikey-agent | touchid-agent |
|---|---|
| `brew install yubikey-agent` | `brew install touchid-agent` |
| `yubikey-agent -setup` | `touchid-agent -create ssh` |
| (single key only) | `touchid-agent -create git -no-touch` |
| `~/Library/Caches/...sock` | (per `IdentityAgent` line in `~/.ssh/config`) |
| Touch YubiKey on each ssh | Touch ID on each ssh |

Plus the hard-stop note: **YubiKey keys cannot be migrated**; you must
re-create on touchid-agent and update authorized_keys on every host.

## 2. Homebrew readiness

### 2.1 Universal binary

Currently host-arch only (single `swiftc -target` and one `go build`).
For Homebrew distribution we need both arm64 and x86_64. Per spec §8.5:

1. Build `libsecureenclave.a` for both architectures and `lipo -create`
   them.
2. Build the Go binary twice (`GOARCH=amd64` and `GOARCH=arm64`),
   linking against the universal `.a`.
3. `lipo -create` the two Go binaries into a single fat Mach-O.

**Action:** add a `make universal` target that produces
`touchid-agent` as a fat binary. Keep `make build` as host-arch for
fast dev loop.

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

### 3.3 Update shell completions for `-software` rule

`contrib/completions/touchid-agent.{bash,zsh}` still list `-software`
as a free-standing flag. They won't error users, but they could include
a comment that `-software` requires `-no-touch`. Low priority.

### 3.4 Fix self-test error wording on recoverable failures

If biometry is locked out at create time, the self-test fires `Sign:`
through CryptoKit and gets back a verbose `LAError -8 "Biometry is
locked out"`. We currently log `"The key is unusable; this likely
indicates a bug. Please report."` — which is wrong for this case.

**Action:** classify the common `LAError` codes (`-2 userCancel`, `-6
biometryNotAvailable`, `-7 biometryNotEnrolled`, `-8 biometryLockout`)
and produce friendly errors. For lockout specifically, mention that
unlocking the Mac with password recovers Touch ID. The key file is
already on disk and valid; the message should reflect that it's
temporarily unusable, not corrupted.

### 3.5 Decide on `-post-hook` semantics

Pre-existing: `exec.Command(hookCmd)` treats the whole flag value as a
single executable path, so `-post-hook 'echo $TOUCHID_AGENT_PUBKEY'`
fails (no executable named `echo $TOUCHID_AGENT_PUBKEY`). Two options:

- **Option A:** wrap in `sh -c` to support inline shell snippets. Matches
  the spirit of the README/example. Adds a small attack surface (shell
  metachars in the user-supplied flag) but the flag is user-supplied
  anyway.
- **Option B:** document explicitly that `-post-hook` takes a path to
  an executable, and fix the docs/examples. Lower-risk; matches current
  behavior.

Option B is the conservative choice and what's already implemented; just
needs the docs to match.

## 4. Polish & deferred

These do not block the two main goals. Capture and revisit.

- [ ] Error classification beyond §3.4 — wrap the worst CryptoKit
      `Error Domain= ...NSDebugDescription=... NSLocalizedDescription=...`
      blobs with cleaner messages.
- [ ] `docs/git-signing.md` could include the SSH allowed-signers file
      setup so `git log --show-signature` works locally.
- [ ] Optional `touchid-agent -migrate-keychain` tool that reads the
      pre-CryptoKit keychain items via legacy code and writes JSON
      files. Spec §10.4 punted on this; users were told to re-create.
      Reconsider only if anyone actually upgrades from a pre-migration
      install.
- [ ] Consider a `touchid-agent -version` flag (currently shown in the
      stderr banner only).
- [ ] launchd: investigate `Sockets` key for socket-activation rather
      than `RunAtLoad + KeepAlive`. Lower idle footprint, faster
      first-connection latency.
