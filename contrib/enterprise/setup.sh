#!/bin/bash
set -euo pipefail

# Enterprise touchid-agent provisioning template.
#
# This is a starting point for organizations that need to:
#   1. Authenticate the user against a corporate identity provider
#   2. Create touchid-agent keys (authentication + signing)
#   3. Register public keys with an internal API
#   4. Configure the launchd service
#
# Customize the variables below for your environment, then distribute
# this script alongside the touchid-agent binary via your MDM/MSC.

# ---------------------------------------------------------------------------
# Configuration — replace these with your organization's values
# ---------------------------------------------------------------------------

# API endpoint for key registration. Override with an environment variable
# or replace the default.
APISERVER="${KEY_REGISTRATION_URL:-https://keyserver.example.com}"

# How to discover the local username. Common options:
#   - Read from a file written by your MDM:  tr -d '[:space:]' < /etc/OWNER
#   - Use the macOS console user:            stat -f '%Su' /dev/console
#   - Use the login name:                    logname
USERNAME=$(stat -f '%Su' /dev/console)

# Paths — adjust if your MDM installs to a different prefix.
TOUCHID_AGENT="/usr/local/bin/touchid-agent"
PLIST_SRC="/usr/local/share/touchid-agent/touchid-agent.plist"
PLIST_DST="$HOME/Library/LaunchAgents/touchid-agent.plist"
SOCKET_DIR="$HOME/Library/Caches/touchid-agent"
SOCKET="$SOCKET_DIR/agent.sock"

# API paths — replace with your identity provider / key registration endpoints.
AUTH_ENDPOINT="$APISERVER/v1/ping"
REGISTER_ENDPOINT="$APISERVER/v1/ssh"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

if [[ ! -x "$TOUCHID_AGENT" ]]; then
    echo "Error: touchid-agent not found at $TOUCHID_AGENT" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Authenticate the user
# ---------------------------------------------------------------------------

echo "Verifying credentials for $USERNAME..."
echo -n "Password: "
read -rs PASSWORD
echo

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "$USERNAME:$PASSWORD" \
    "$AUTH_ENDPOINT")

if [[ "$HTTP_STATUS" != "200" ]]; then
    echo "Error: authentication failed (HTTP $HTTP_STATUS)." >&2
    exit 1
fi
echo "Authentication successful."

# ---------------------------------------------------------------------------
# Step 2: Stop existing agents
# ---------------------------------------------------------------------------

launchctl unload "$PLIST_DST" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 3: Clean up any existing touchid-agent keys
# ---------------------------------------------------------------------------

"$TOUCHID_AGENT" -delete-all 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 4: Create keys
# ---------------------------------------------------------------------------
# Typical enterprise setup: one key with Touch ID for interactive SSH,
# one no-touch key for git signing / automation.

"$TOUCHID_AGENT" -create ssh
"$TOUCHID_AGENT" -create git -no-touch

# ---------------------------------------------------------------------------
# Step 5: Read public keys
# ---------------------------------------------------------------------------

SSH_PUBKEY=$(cat ~/.ssh/touchid-agent-ssh.pub)
GIT_PUBKEY=$(cat ~/.ssh/touchid-agent-git.pub)

# Strip the comment field — most APIs only want "type base64key".
SSH_KEY_ONLY=$(echo "$SSH_PUBKEY" | awk '{print $1" "$2}')
GIT_KEY_ONLY=$(echo "$GIT_PUBKEY" | awk '{print $1" "$2}')

# ---------------------------------------------------------------------------
# Step 6: Register keys with the corporate API
# ---------------------------------------------------------------------------
# Adapt the payload and endpoint to match your key registration API.

echo "Registering public keys..."

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "$USERNAME:$PASSWORD" \
    -H "Content-Type: application/json" \
    -X POST "$REGISTER_ENDPOINT" \
    -d "{\"auth_key\": \"$SSH_KEY_ONLY\", \"signing_key\": \"$GIT_KEY_ONLY\"}")

if [[ "$HTTP_STATUS" != "200" && "$HTTP_STATUS" != "201" ]]; then
    echo "Error: Failed to register keys (HTTP $HTTP_STATUS)." >&2
    echo "Keys were created locally but NOT registered on servers." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 7: Configure launchd
# ---------------------------------------------------------------------------

mkdir -p "$SOCKET_DIR"
mkdir -p "$(dirname "$PLIST_DST")"
sed -e "s|__BINARY__|$TOUCHID_AGENT|g" \
    -e "s|__HOME__|$HOME|g" \
    "$PLIST_SRC" > "$PLIST_DST"
launchctl load "$PLIST_DST"

# ---------------------------------------------------------------------------
# Step 8: Configure shell
# ---------------------------------------------------------------------------

SHELL_RC="$HOME/.zshrc"
SOCK_LINE="export SSH_AUTH_SOCK=\"$SOCKET\""

if ! grep -q 'touchid-agent' "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# touchid-agent" >> "$SHELL_RC"
    echo "$SOCK_LINE" >> "$SHELL_RC"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "Done. touchid-agent is configured and running."
echo ""
echo "SSH public key (authentication, Touch ID required):"
echo "  $SSH_PUBKEY"
echo ""
echo "Git public key (signing, no Touch ID):"
echo "  $GIT_PUBKEY"
echo ""
echo "Restart your terminal, then verify with: ssh-add -L"
echo ""
