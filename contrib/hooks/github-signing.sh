#!/bin/bash
set -euo pipefail

# Post-create hook: upload SSH public key to GitHub as a signing key
# and configure git to use it for commit signing.
# Requires: gh CLI (https://cli.github.com), authenticated via `gh auth login`.
#
# Usage:
#   touchid-agent -create git -no-touch -post-hook contrib/hooks/github-signing.sh

if ! command -v gh &>/dev/null; then
    echo "Error: gh CLI not found. Install from https://cli.github.com" >&2
    exit 1
fi

gh ssh-key add "$TOUCHID_AGENT_PUBKEY_FILE" \
    --title "touchid-agent:${TOUCHID_AGENT_LABEL}" \
    --type signing

git config --global gpg.format ssh
git config --global user.signingkey "$TOUCHID_AGENT_PUBKEY_FILE"
git config --global commit.gpgsign true

echo "Signing key uploaded to GitHub and git configured for SSH commit signing."
