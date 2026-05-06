# Release process

A release of `touchid-agent` consists of:

1. A signed, notarized universal Mach-O binary (`.tar.gz` and `.zip`).
2. SHA-256 sidecar files for both archives.
3. A GitHub release with auto-generated notes.
4. A bumped Homebrew formula in the tap repo.

The intended path is **fully automated** via the GitHub Actions workflow
at `.github/workflows/release.yml`, triggered on a `vX.Y.Z` tag push.
Manual fallback is documented at the bottom of this file.

## One-time setup

### 1. Apple Developer credentials

You need an active Apple Developer Program membership.

- **Developer ID Application certificate** for code signing.
  Generate from <https://developer.apple.com/account/resources/certificates>,
  install in Keychain Access, then export the cert + private key as a
  `.p12` (e.g. `developer-id.p12`).

- **App-specific password** for `notarytool`.
  Generate at <https://appleid.apple.com> → Sign-In and Security → App-Specific Passwords.
  Save the resulting `xxxx-xxxx-xxxx-xxxx` string.

- **Team ID** (10-char alphanumeric).
  Find at <https://developer.apple.com/account> under Membership Details.

### 2. Local keychain profile (optional, for manual releases)

To avoid passing credentials on every `make notarize`:

```bash
xcrun notarytool store-credentials touchid-agent-notary \
  --apple-id "you@example.com" \
  --team-id "ABCD123456" \
  --password "xxxx-xxxx-xxxx-xxxx"
```

Then `make notarize NOTARY_PROFILE=touchid-agent-notary`.

### 3. GitHub Actions secrets

Set the following on the repo (Settings → Secrets and variables → Actions):

| Secret | Value |
|---|---|
| `MACOS_CERTIFICATE` | `base64 -i developer-id.p12 \| pbcopy` then paste |
| `MACOS_CERTIFICATE_PASSWORD` | password used when exporting the `.p12` |
| `KEYCHAIN_PASSWORD` | any random string; used for the ephemeral runner keychain |
| `MACOS_SIGN_IDENTITY` | the certificate's common name, e.g. `Developer ID Application: Your Name (ABCD123456)` |
| `APPLE_ID` | your Apple ID email |
| `APPLE_TEAM_ID` | 10-char team ID |
| `APPLE_APP_SPECIFIC_PASSWORD` | the `xxxx-xxxx-xxxx-xxxx` password |
| `HOMEBREW_TAP_TOKEN` | PAT (classic, `repo` scope) or fine-grained token with read/write on `ignaciojimenez/homebrew-tap` |

Find the exact `MACOS_SIGN_IDENTITY` string with:

```bash
security find-identity -v -p codesigning
```

### 4. Homebrew tap repo (one-time)

```bash
gh repo create ignaciojimenez/homebrew-tap --public \
  --description "Personal Homebrew tap"
```

The tap layout is `Formula/touchid-agent.rb`. Copy
`contrib/homebrew/touchid-agent.rb` into that path on each release.

## Cutting a release

```bash
# 1. Make sure main is clean and tests pass.
make test

# 2. Tag and push. CI does the rest.
git tag -s v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The `Release` workflow will:

1. Check out the tag.
2. Import the Developer ID certificate into a temporary keychain.
3. Build the universal binary (`make universal`).
4. Code-sign with hardened runtime + secure timestamp.
5. Package `.zip` + `.tar.gz` with SHA-256 sidecars.
6. Submit the `.zip` to Apple's notary service and `--wait` for the result.
7. Generate release notes from `git log` since the previous tag.
8. Create the GitHub release with all four artifacts attached.
9. Tear down the keychain.
10. (separate job) Update the `ignaciojimenez/homebrew-tap` formula with the new version and SHA-256.

The full pipeline takes ~5–10 minutes, mostly notarization wait time.

## Updating the Homebrew formula

The `update-homebrew` job in `release.yml` automatically updates the
formula in `ignaciojimenez/homebrew-tap` after a successful release.
No manual intervention needed — push a tag and both the release and the
formula update happen end-to-end.

### One-time setup

Add `HOMEBREW_TAP_TOKEN` to the repo secrets (Settings → Secrets →
Actions). This must be a **Personal Access Token** (classic, with
`repo` scope) or a fine-grained token with read/write access to the
`ignaciojimenez/homebrew-tap` repository.

### Manual fallback

If the `update-homebrew` job fails or you need to update outside CI:

```bash
VERSION=v0.1.0
SHA256=$(curl -sL "https://github.com/ignaciojimenez/touchid-agent/releases/download/${VERSION}/touchid-agent-${VERSION}-darwin-universal.tar.gz.sha256" | awk '{print $1}')

# In the tap repo:
sed -i '' \
  -e "s/^  version \".*\"/  version \"${VERSION#v}\"/" \
  -e "s/^  sha256 \".*\"/  sha256 \"${SHA256}\"/" \
  Formula/touchid-agent.rb

git commit -am "touchid-agent ${VERSION}"
git push
```

End users then get the update via `brew update && brew upgrade touchid-agent`.

## Verifying a release locally

```bash
shasum -a 256 -c touchid-agent-v0.1.0-darwin-universal.tar.gz.sha256
codesign -dv --verbose=4 touchid-agent
spctl -a -t exec -vv touchid-agent   # Gatekeeper assessment (online)
```

`spctl` will report `accepted source=Notarized Developer ID` once
notarization is in place.

## Manual release (fallback)

If GitHub Actions is unavailable:

```bash
make release \
  CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
  NOTARY_PROFILE=touchid-agent-notary \
  VERSION=v0.1.0

make release-notes VERSION=v0.1.0 > dist/RELEASE_NOTES.md

gh release create v0.1.0 \
  --title "touchid-agent v0.1.0" \
  --notes-file dist/RELEASE_NOTES.md \
  dist/touchid-agent-v0.1.0-darwin-universal.{tar.gz,tar.gz.sha256,zip,zip.sha256}
```

## Stapling

`xcrun stapler staple` only supports `.app` bundles, `.dmg`, and `.pkg`.
Flat Mach-O CLI binaries cannot be stapled. Gatekeeper validates the
notarization ticket online on first launch and caches the result. Users
on an air-gapped network at first launch will get a Gatekeeper prompt;
this is consistent with how other CLI tools (e.g. `age-plugin-se`) are
distributed.
