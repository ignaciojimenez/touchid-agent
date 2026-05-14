#!/bin/bash
#
# build-mobileconfig.sh — produce a signed .mobileconfig configuration
# profile that pins touchid-agent runtime flags via macOS Managed
# Preferences.
#
# Inputs:
#   - $1 (or $VERSION env): version tag, e.g. v0.5.0.
#
# Optional environment for signing:
#   MACOS_INSTALLER_SIGN_IDENTITY  — Developer ID Installer identity
#                                    from `security find-identity -v`.
#
# If MACOS_INSTALLER_SIGN_IDENTITY is unset, an unsigned .mobileconfig
# is produced for development / inspection.
#
# Output:
#   dist/touchid-agent-<version>.mobileconfig
#
# The profile ships sensible fleet defaults. IT should customise the
# values before deploying via MDM (Munki, Jamf, Mosyle, Kandji).
#
# Managed keys (bundle ID: com.ignaciojimenez.touchid-agent):
#
#   audit_log_path  (string)  — path to JSON-lines audit log
#   peer_check      (boolean) — verify peer binary against allowlist
#   rate_limit      (integer) — max signing ops per key per minute
#   allowed_callers (string)  — path to file listing allowed callers
#
# The agent reads these via CFPreferencesCopyAppValue. Managed values
# override the matching CLI flag unconditionally.

set -euo pipefail

VERSION="${1:-${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
BUNDLE_ID="com.ignaciojimenez.touchid-agent"
PROFILE_UUID="A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
PAYLOAD_UUID="F0E1D2C3-B4A5-6789-0ABC-DEF123456789"

FILENAME="touchid-agent-${VERSION}.mobileconfig"
UNSIGNED="$DIST/${FILENAME}.unsigned"
SIGNED="$DIST/$FILENAME"

mkdir -p "$DIST"

# 1. Render the unsigned profile XML.
cat > "$UNSIGNED" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.ManagedClient.preferences</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>${BUNDLE_ID}.managed-preferences</string>
      <key>PayloadUUID</key>
      <string>${PAYLOAD_UUID}</string>
      <key>PayloadEnabled</key>
      <true/>
      <key>PayloadDisplayName</key>
      <string>touchid-agent Policy</string>
      <key>PayloadDescription</key>
      <string>Enforces runtime flags for touchid-agent via Managed Preferences.</string>
      <key>PayloadContent</key>
      <dict>
        <key>${BUNDLE_ID}</key>
        <dict>
          <key>Forced</key>
          <array>
            <dict>
              <key>mcx_preference_settings</key>
              <dict>
                <key>audit_log_path</key>
                <string>/var/log/touchid-agent/audit.log</string>
                <key>peer_check</key>
                <true/>
                <key>rate_limit</key>
                <integer>30</integer>
              </dict>
            </dict>
          </array>
        </dict>
      </dict>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>touchid-agent Configuration</string>
  <key>PayloadDescription</key>
  <string>Configuration profile for touchid-agent ${VERSION}. Enforces audit logging, peer verification, and rate limiting via macOS Managed Preferences. Customise values before deploying to your fleet.</string>
  <key>PayloadIdentifier</key>
  <string>${BUNDLE_ID}.profile</string>
  <key>PayloadOrganization</key>
  <string>ignaciojimenez</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadScope</key>
  <string>System</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${PROFILE_UUID}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
PLIST

# 2. Sign with Developer ID Installer if available; otherwise ship unsigned.
if [[ -n "${MACOS_INSTALLER_SIGN_IDENTITY:-}" ]]; then
  /usr/bin/security cms -S \
    -N "$MACOS_INSTALLER_SIGN_IDENTITY" \
    -i "$UNSIGNED" \
    -o "$SIGNED"
  rm -f "$UNSIGNED"
  echo "Signed profile: $SIGNED"
else
  mv "$UNSIGNED" "$SIGNED"
  echo "warning: MACOS_INSTALLER_SIGN_IDENTITY unset; producing unsigned profile (development only)" >&2
fi

echo
echo "Profile built: $SIGNED"
ls -lh "$SIGNED"
