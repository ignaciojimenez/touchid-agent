#!/bin/bash
#
# build-pkg.sh — produce a signed, notarized .pkg installer for
# system-wide / fleet deployment of touchid-agent.
#
# Inputs:
#   - $1 (or $VERSION env): version tag, e.g. v0.4.0. Defaults to
#     `git describe --tags --always`.
#   - touchid-agent binary in the repo root, signed with Developer ID
#     Application (run `make universal sign` first).
#
# Optional environment for signing / notarization:
#   MACOS_INSTALLER_SIGN_IDENTITY  — full identity string from
#                                    `security find-identity -v`
#   APPLE_ID, APPLE_TEAM_ID, APPLE_PASSWORD
#                                  — notarytool credentials (the same
#                                    ones used for the binary release)
#
# If MACOS_INSTALLER_SIGN_IDENTITY is unset, an unsigned .pkg is built
# for local development. Notarization runs only when both signing and
# all three notary credentials are present.
#
# Output:
#   dist/touchid-agent-<version>.pkg
#   dist/touchid-agent-<version>.pkg.sha256

set -euo pipefail

VERSION="${1:-${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}}"
VERSION_BARE="${VERSION#v}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
WORK="$DIST/pkg-work"
PAYLOAD="$WORK/payload"
SCRIPTS="$WORK/scripts"
BUNDLE_ID="com.ignaciojimenez.touchid-agent"

PKG_FILENAME="touchid-agent-${VERSION}.pkg"
COMPONENT_PKG="$WORK/touchid-agent-component.pkg"
UNSIGNED_PRODUCT="$WORK/touchid-agent-unsigned.pkg"
PRODUCT_PKG="$DIST/$PKG_FILENAME"

# 1. Verify the binary exists. In signed-output mode also verify it has
#    a Developer ID Application signature (ad-hoc / unsigned binaries
#    won't pass Gatekeeper inside a signed pkg). In dev mode we accept
#    anything so the pkg flow can be exercised locally.
if [[ ! -f "$ROOT/touchid-agent" ]]; then
  echo "error: $ROOT/touchid-agent missing — run 'make universal sign' first" >&2
  exit 1
fi
if [[ -n "${MACOS_INSTALLER_SIGN_IDENTITY:-}" ]]; then
  if codesign -dv "$ROOT/touchid-agent" 2>&1 | grep -q "adhoc"; then
    echo "error: binary is ad-hoc signed; signed pkg requires a Developer ID Application binary" >&2
    exit 1
  fi
  if ! codesign -dv "$ROOT/touchid-agent" 2>&1 | grep -q "Authority="; then
    echo "error: binary appears unsigned; signed pkg requires a Developer ID Application binary" >&2
    exit 1
  fi
fi

# 2. Lay out the pkg payload tree mirroring the install destination.
rm -rf "$WORK"
mkdir -p "$PAYLOAD/usr/local/bin"
mkdir -p "$PAYLOAD/Library/LaunchAgents"
mkdir -p "$SCRIPTS"

install -m 755 "$ROOT/touchid-agent" "$PAYLOAD/usr/local/bin/touchid-agent"
install -m 644 "$ROOT/scripts/pkg/Library/LaunchAgents/touchid-agent-bootstrap.plist" \
               "$PAYLOAD/Library/LaunchAgents/touchid-agent-bootstrap.plist"
install -m 755 "$ROOT/scripts/pkg/postinstall" "$SCRIPTS/postinstall"

# 3. Build the component pkg.
pkgbuild \
  --root "$PAYLOAD" \
  --scripts "$SCRIPTS" \
  --identifier "$BUNDLE_ID" \
  --version "$VERSION_BARE" \
  --install-location "/" \
  --ownership recommended \
  "$COMPONENT_PKG"

# 4. Render the distribution.xml with the version baked in, then build
#    the product (distribution) pkg.
mkdir -p "$WORK"
sed "s/__VERSION__/$VERSION_BARE/g" "$ROOT/scripts/pkg/distribution.xml" > "$WORK/distribution.xml"

productbuild \
  --distribution "$WORK/distribution.xml" \
  --package-path "$WORK" \
  "$UNSIGNED_PRODUCT"

# 5. Sign with Developer ID Installer if available; otherwise dev path.
if [[ -n "${MACOS_INSTALLER_SIGN_IDENTITY:-}" ]]; then
  productsign \
    --sign "$MACOS_INSTALLER_SIGN_IDENTITY" \
    "$UNSIGNED_PRODUCT" \
    "$PRODUCT_PKG"
else
  echo "warning: MACOS_INSTALLER_SIGN_IDENTITY unset; producing unsigned pkg (development only)" >&2
  cp "$UNSIGNED_PRODUCT" "$PRODUCT_PKG"
fi

# 6. Notarize and staple if both signed and notary creds available.
if [[ -n "${MACOS_INSTALLER_SIGN_IDENTITY:-}" \
   && -n "${APPLE_ID:-}" \
   && -n "${APPLE_TEAM_ID:-}" \
   && -n "${APPLE_PASSWORD:-}" ]]; then
  echo "Submitting $PRODUCT_PKG to Apple notary service (this can take a few minutes)..."
  xcrun notarytool submit "$PRODUCT_PKG" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_PASSWORD" \
    --wait
  echo "Stapling notarization ticket..."
  xcrun stapler staple "$PRODUCT_PKG"
elif [[ -n "${MACOS_INSTALLER_SIGN_IDENTITY:-}" ]]; then
  echo "warning: signed pkg built but notary credentials missing; skipping notarization" >&2
fi

# 7. SHA-256 sidecar and cleanup.
( cd "$DIST" && shasum -a 256 "$PKG_FILENAME" > "$PKG_FILENAME.sha256" )
rm -rf "$WORK"

echo
echo "Pkg built: $PRODUCT_PKG"
ls -lh "$PRODUCT_PKG" "$PRODUCT_PKG.sha256"
echo
echo "SHA-256:"
cat "$PRODUCT_PKG.sha256"
