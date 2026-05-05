# TODO

## 1. First tagged release

Everything required to cut `v0.1.0` is in place; the remaining work is
operational, not code. The three blocks below are roughly **30–60 min of
hands-on work spread over a few days** (Apple cert provisioning has its
own latency).

### 1.1 One-time Apple Developer setup

You need an active Apple Developer Program membership (USD $99/year).
If that is not in place yet, sign up at
<https://developer.apple.com/programs/enroll/>. Enrollment can take
a couple of business days for individuals.

Once enrolled, you need three artifacts before touching this repo:

1. **Developer ID Application certificate** (one-time per machine).
2. **App-specific password** for `notarytool` (one-time per Apple ID).
3. **Team ID** (look it up once; it never changes).

#### 1.1.1 Generate the Developer ID Application certificate

```bash
# 1. Create a Certificate Signing Request (CSR).
#    Keychain Access → Certificate Assistant → Request a Certificate
#    From a Certificate Authority…
#    - User Email Address: your Apple ID
#    - Common Name: anything ("Ignacio Jiménez Dev ID" works)
#    - "Saved to disk" + "Let me specify key pair information"
#    - Key Size 2048, Algorithm RSA
#    Save as ~/Downloads/CertificateSigningRequest.certSigningRequest
```

Then in a browser:

1. <https://developer.apple.com/account/resources/certificates>
2. Click **+**, choose **Developer ID Application**, Continue.
3. Upload the CSR, Continue, Download `developerID_application.cer`.
4. Double-click the `.cer` to install it into `login` keychain.

Export the cert + private key as a `.p12`:

```bash
# In Keychain Access:
#   - Search "Developer ID Application"
#   - Expand the cert; Cmd-click the cert AND its private key
#   - Right-click → "Export 2 items…"
#   - Save as ~/Downloads/developer-id.p12 with a strong password
#     (you will paste this password into MACOS_CERTIFICATE_PASSWORD).
```

Verify locally:

```bash
security find-identity -v -p codesigning
# Should print a line like:
#   1) ABCDEF1234... "Developer ID Application: Ignacio Jiménez (XYZ1234567)"
# Save that exact quoted string — it is your MACOS_SIGN_IDENTITY.
```

#### 1.1.2 Generate the app-specific password

1. <https://appleid.apple.com> → Sign-In and Security → **App-Specific Passwords**.
2. Generate a new one labelled `touchid-agent-notarize`.
3. Copy the `xxxx-xxxx-xxxx-xxxx` string to a password manager. Apple
   will not show it again.

#### 1.1.3 Find your Team ID

<https://developer.apple.com/account> → Membership Details → 10-char
alphanumeric **Team ID** (e.g. `XYZ1234567`).

### 1.2 Provision the GitHub Actions secrets

All of these go on the **touchid-agent** repo (not the tap repo):
Settings → Secrets and variables → Actions → New repository secret.
You can also use `gh`:

```bash
cd ~/Documents/Workspaces/touchid-agent

# Base64-encode the .p12 and load it into the secret in one shot
base64 -i ~/Downloads/developer-id.p12 | gh secret set MACOS_CERTIFICATE

# These prompt for the value (paste then ↵, Ctrl-D):
gh secret set MACOS_CERTIFICATE_PASSWORD       # the .p12 password from 1.1.1
gh secret set KEYCHAIN_PASSWORD                # any random string, e.g. `openssl rand -hex 16`
gh secret set MACOS_SIGN_IDENTITY              # the full "Developer ID Application: …" string from 1.1.1
gh secret set APPLE_ID                         # your Apple ID email
gh secret set APPLE_TEAM_ID                    # 10-char team ID from 1.1.3
gh secret set APPLE_APP_SPECIFIC_PASSWORD      # the xxxx-xxxx-xxxx-xxxx from 1.1.2
```

Verify everything is set:

```bash
gh secret list
# Should show 7 secrets.
```

After this, deletion of the `.p12` from `~/Downloads` is recommended;
the secret is now persisted in GitHub.

### 1.3 Cut the release

```bash
# Pre-flight: clean tree + green tests
git status                       # must be clean
make test                        # must be all PASS
make vuln                        # must report "No vulnerabilities found"

# Tag the release. NOTE: do not use -s here unless you are at the
# keyboard — Secretive will prompt for biometric auth on every signed
# tag. An unsigned annotated tag is fine for this project.
git tag v0.1.0 -m "v0.1.0"
git push origin v0.1.0

# Watch the workflow:
gh run watch
# or in a browser: https://github.com/ignaciojimenez/touchid-agent/actions
```

Expected timeline: ~5–10 min. Most of that is Apple's notary service.

If the workflow fails, the most common causes are:

| Failure | Likely cause |
|---|---|
| `errSecInternalComponent` during signing | `MACOS_SIGN_IDENTITY` does not match the cert's actual CN |
| `Invalid Apple credentials` | `APPLE_APP_SPECIFIC_PASSWORD` typo, or password expired (regenerate at appleid.apple.com) |
| `The bundle is not signed` from notarytool | The signing step ran but didn't apply hardened runtime; check `make sign` output in the workflow logs |
| Workflow does not start | Tag does not match `v*` glob; check `git tag -l` and the trigger in `.github/workflows/release.yml` |

When it succeeds, the release will be at
<https://github.com/ignaciojimenez/touchid-agent/releases/tag/v0.1.0>
with four artifacts attached (`.tar.gz`, `.tar.gz.sha256`, `.zip`,
`.zip.sha256`).

### 1.4 Publish the Homebrew formula

The end-user goal is `brew tap ignaciojimenez/tap && brew install touchid-agent`.
That requires a separate repository named exactly
`ignaciojimenez/homebrew-tap` (the `homebrew-` prefix is what makes
`brew tap ignaciojimenez/tap` resolve).

```bash
# Create the tap repo
gh repo create ignaciojimenez/homebrew-tap --public \
  --description "Personal Homebrew tap"

# Clone it next to touchid-agent
cd ~/Documents/Workspaces
gh repo clone ignaciojimenez/homebrew-tap
cd homebrew-tap
mkdir -p Formula

# Pull the SHA-256 from the published release
VERSION=v0.1.0
SHA256=$(curl -sL \
  "https://github.com/ignaciojimenez/touchid-agent/releases/download/${VERSION}/touchid-agent-${VERSION}-darwin-universal.tar.gz.sha256" \
  | awk '{print $1}')
echo "$SHA256"   # sanity check: should be 64 hex chars

# Copy the formula and patch in the real version + sha256
cp ../touchid-agent/contrib/homebrew/touchid-agent.rb Formula/touchid-agent.rb
sed -i '' \
  -e "s/^  version \".*\"/  version \"${VERSION#v}\"/" \
  -e "s/^  sha256 \".*\"/  sha256 \"${SHA256}\"/" \
  Formula/touchid-agent.rb

# Commit and publish
git add Formula/touchid-agent.rb
git commit --no-gpg-sign -m "touchid-agent ${VERSION}"
git push -u origin main

# End-to-end install test (on this Mac or a clean one):
brew tap ignaciojimenez/tap
brew install touchid-agent
which touchid-agent          # should be /opt/homebrew/bin/touchid-agent (Apple Silicon) or /usr/local/bin/touchid-agent (Intel)
touchid-agent -version       # should print v0.1.0
codesign -dv --verbose=4 "$(which touchid-agent)" 2>&1 | grep -i 'authority\|notarized'
# Expected output includes:
#   Authority=Developer ID Application: Your Name (TEAMID)
#   Authority=Developer ID Certification Authority
#   Authority=Apple Root CA
#   Notarized=accepted
```

If `codesign` does not show `Notarized=accepted`, the binary still works
(Gatekeeper checks online on first launch and caches the result), but
you should investigate — it usually means the workflow's `notarize`
step silently `--no-wait`'d or the `.zip` was wrong.

### 1.5 Subsequent releases

Once 1.1–1.4 are done, future releases are:

```bash
# In touchid-agent repo
git tag vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
gh run watch

# In homebrew-tap repo, after the release succeeds
VERSION=vX.Y.Z
SHA256=$(curl -sL \
  "https://github.com/ignaciojimenez/touchid-agent/releases/download/${VERSION}/touchid-agent-${VERSION}-darwin-universal.tar.gz.sha256" \
  | awk '{print $1}')
sed -i '' \
  -e "s/^  version \".*\"/  version \"${VERSION#v}\"/" \
  -e "s/^  sha256 \".*\"/  sha256 \"${SHA256}\"/" \
  Formula/touchid-agent.rb
git commit --no-gpg-sign -am "touchid-agent ${VERSION}" && git push
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
