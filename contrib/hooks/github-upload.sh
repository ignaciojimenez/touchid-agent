#!/bin/bash
set -euo pipefail

# Post-create hook: upload SSH public key to GitHub.
# Requires: gh CLI (https://cli.github.com), authenticated via `gh auth login`.
#
# Usage:
#   touchid-agent -create ssh --post-hook contrib/hooks/github-upload.sh

if ! command -v gh &>/dev/null; then
    echo "Error: gh CLI not found. Install from https://cli.github.com" >&2
    exit 1
fi

gh ssh-key add "$TOUCHID_AGENT_PUBKEY_FILE" \
    --title "touchid-agent:${TOUCHID_AGENT_LABEL}" \
    --type authentication

echo "Public key uploaded to GitHub as 'touchid-agent:${TOUCHID_AGENT_LABEL}'"
