#!/bin/bash
set -euo pipefail

# Wipe all touchid-agent keys and re-run the enterprise setup script.
# Adjust the path below to match where your MDM installs the setup script.

SETUP_SCRIPT="/usr/local/bin/enterprise-touchid-setup"

/usr/local/bin/touchid-agent -delete-all
exec "$SETUP_SCRIPT"
