#!/bin/bash
set -euo pipefail

# Example post-create hook for touchid-agent.
# This script authenticates with a custom corporate API and registers
# the newly created SSH public key.
#
# To use:
#   chmod +x contrib/hooks/custom-api-upload.sh
#   touchid-agent -create ssh -post-create-hook contrib/hooks/custom-api-upload.sh

APISERVER="${KEY_REGISTRATION_URL:-https://keyserver.example.com}"
REGISTER_ENDPOINT="$APISERVER/v1/ssh"

# The agent passes these environment variables to the hook
LABEL="${TOUCHID_AGENT_KEY_LABEL}"
PUBKEY="${TOUCHID_AGENT_PUBKEY}"

# Extract just the type and base64 blob (strip any trailing comments)
KEY_ONLY=$(echo "$PUBKEY" | awk '{print $1" "$2}')

# Read credentials from the active terminal
USERNAME=$(stat -f '%Su' /dev/console)
echo "Verifying credentials for $USERNAME to register key '$LABEL'..."
echo -n "Password: "
read -rs PASSWORD < /dev/tty
echo ""

echo "Registering public key with $REGISTER_ENDPOINT..."

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "$USERNAME:$PASSWORD" \
    -H "Content-Type: application/json" \
    -X POST "$REGISTER_ENDPOINT" \
    -d "{\"label\": \"$LABEL\", \"public_key\": \"$KEY_ONLY\"}")

if [[ "$HTTP_STATUS" != "200" && "$HTTP_STATUS" != "201" ]]; then
    echo "Error: Failed to register key (HTTP $HTTP_STATUS)." >&2
    exit 1
fi

echo "Key successfully registered."
