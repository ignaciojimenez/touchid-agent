#!/bin/bash
# Generate a release-notes draft for the given tag.
#
# Usage: scripts/release-notes.sh <version>
#
# Prints a Markdown draft to stdout. Diffs against the previous tag (or the
# initial commit if there is no previous tag). Intended to be reviewed and
# edited before publishing.

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: $0 <version>" >&2
  exit 1
fi

PREV_TAG="$(git describe --tags --abbrev=0 --match 'v*' "${VERSION}^" 2>/dev/null || true)"
if [[ -z "$PREV_TAG" ]]; then
  RANGE="$(git rev-list --max-parents=0 HEAD | tail -1)..HEAD"
  PREV_LABEL="initial commit"
else
  RANGE="${PREV_TAG}..HEAD"
  PREV_LABEL="$PREV_TAG"
fi

cat <<EOF
# touchid-agent ${VERSION}

macOS SSH agent backed by the Secure Enclave and Touch ID. Drop-in
replacement for yubikey-agent.

## Changes since ${PREV_LABEL}

EOF

git log --pretty=format:'- %s' "$RANGE"

cat <<'EOF'


## Verifying this release

\`\`\`
shasum -a 256 -c touchid-agent-VERSION-darwin-universal.tar.gz.sha256
\`\`\`

The binary is signed with a Developer ID certificate and notarized by Apple.
Gatekeeper validates the notarization ticket online on first launch (flat
Mach-O CLI binaries cannot be stapled).

## Installing

\`\`\`
tar -xzf touchid-agent-VERSION-darwin-universal.tar.gz
sudo install -m 755 touchid-agent /usr/local/bin/
\`\`\`

See README.md for SSH config and launchd setup.
EOF
