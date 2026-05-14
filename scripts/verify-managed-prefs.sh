#!/bin/bash
#
# verify-managed-prefs.sh — end-to-end verification of the Managed
# Preferences read path and .mobileconfig profile (Track #2 §3).
#
# WHAT THIS SCRIPT DOES
#
#   1. Stops the production touchid-agent (if running) so test values
#      cannot leak into a live agent process. Restarts it when done.
#   2. Phase 0: starts a fresh agent with no managed prefs, asserts no
#      override log lines appear (baseline sanity check).
#   3. Phase 1: writes test values to the user preference domain via
#      `defaults write`, starts the agent, asserts all four
#      "Managed preference active:" log lines appear, then cleans up.
#   4. Phase 2 (automatic if a Developer ID Installer cert is found):
#      builds and signs the .mobileconfig, validates the CMS signature,
#      installs the profile via `sudo profiles install`, verifies the
#      agent reads from the managed domain, then removes the profile.
#
#   All state is rolled back via a trap — even on failure or Ctrl-C.
#   The production agent is always restarted.
#
# PREREQUISITES
#
#   - The touchid-agent binary must be built. If missing, the script
#     runs `make build` automatically.
#   - Phase 2 requires a Developer ID Installer certificate in the
#     keychain. The script auto-detects it; if absent, Phase 2 is
#     skipped with a note.
#   - Phase 2 requires sudo for `profiles install` / `profiles remove`.
#
# USAGE
#
#   ./scripts/verify-managed-prefs.sh
#       Runs all phases. Auto-detects signing identity for Phase 2.
#
#   ./scripts/verify-managed-prefs.sh --skip-phase2
#       Runs Phases 0 and 1 only (no sudo, no signing needed).
#
#   ./scripts/verify-managed-prefs.sh "Developer ID Installer: Name (TEAM)"
#       Uses the specified signing identity for Phase 2 instead of
#       auto-detecting.
#
# TROUBLESHOOTING
#
#   "binary not found / make build failed"
#       Xcode Command Line Tools must be installed (provides swiftc).
#       Run `xcode-select --install` if missing.
#
#   "Phase 1 FAIL: no managed-preference log lines"
#       The agent did not pick up values written via `defaults write`.
#       Possible causes:
#       - The CFPreferencesCopyAppValue cgo bridge is broken. Check
#         that `make test` passes, specifically the TestCFPref* tests.
#       - The bundle ID is wrong. The agent reads from
#         com.ignaciojimenez.touchid-agent.
#       - A stale ~/Library/Preferences/com.ignaciojimenez.touchid-agent.plist
#         file exists with unexpected values. Delete it and retry.
#
#   "Phase 2 FAIL: mobileconfig is unsigned XML"
#       `security cms -S` failed silently. Check that the signing
#       identity is a Developer ID Installer (not Application) cert:
#         security find-identity -v | grep "Developer ID Installer"
#
#   "Phase 2 FAIL: profiles install failed"
#       macOS may require user approval for profile installation in
#       System Settings > Privacy & Security > Profiles. On macOS 13+
#       this is expected for manually-installed profiles. In production
#       the profile is pushed via MDM which bypasses this.
#
#   "production agent not restarting"
#       The script reloads the plist via `launchctl load`. If the
#       socket does not appear within 5 seconds, manually reload:
#         launchctl load ~/Library/LaunchAgents/touchid-agent.plist
#       Or run: touchid-agent -install-plist

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────

BUNDLE_ID="com.ignaciojimenez.touchid-agent"
PROFILE_ID="${BUNDLE_ID}.profile"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$ROOT/touchid-agent"
PLIST="$HOME/Library/LaunchAgents/touchid-agent.plist"
PROD_SOCKET="$HOME/Library/Caches/touchid-agent/agent.sock"
TEST_SOCK="/tmp/touchid-agent-verify-$$.sock"
AGENT_LOG="$(mktemp /tmp/touchid-agent-verify-XXXXXX.log)"
SKIP_PHASE2=false
SIGN_IDENTITY=""

# ── Argument parsing ─────────────────────────────────────────────────

if [[ "${1:-}" == "--skip-phase2" ]]; then
    SKIP_PHASE2=true
elif [[ -n "${1:-}" ]]; then
    SIGN_IDENTITY="$1"
fi

# ── State tracking (drives cleanup) ─────────────────────────────────

AGENT_PID=""
PROD_WAS_LOADED=false
PHASE1_PREFS_SET=false
PHASE2_PROFILE_INSTALLED=false
PHASE2_MOBILECONFIG=""
PASS=0
FAIL=0

# ── Cleanup (runs on EXIT — always) ─────────────────────────────────

cleanup() {
    local exit_code=$?
    echo
    echo "=== Cleanup ==="

    # 1. Kill test agent if still running.
    if [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
        echo "  Stopping test agent (PID $AGENT_PID)..."
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    rm -f "$TEST_SOCK"

    # 2. Remove Phase 1 test preferences from user domain.
    if $PHASE1_PREFS_SET; then
        echo "  Removing user-domain test preferences..."
        defaults delete "$BUNDLE_ID" audit_log_path 2>/dev/null || true
        defaults delete "$BUNDLE_ID" peer_check 2>/dev/null || true
        defaults delete "$BUNDLE_ID" rate_limit 2>/dev/null || true
        defaults delete "$BUNDLE_ID" allowed_callers 2>/dev/null || true
    fi

    # 3. Remove Phase 2 profile if still installed.
    if $PHASE2_PROFILE_INSTALLED; then
        echo "  Removing configuration profile..."
        sudo profiles remove -identifier "$PROFILE_ID" 2>/dev/null || true
    fi

    # 4. Remove Phase 2 build artifact.
    if [[ -n "$PHASE2_MOBILECONFIG" ]] && [[ -f "$PHASE2_MOBILECONFIG" ]]; then
        rm -f "$PHASE2_MOBILECONFIG"
    fi

    # 5. Restart production agent if we stopped it.
    if $PROD_WAS_LOADED; then
        echo "  Restarting production agent..."
        launchctl load "$PLIST" 2>/dev/null || true
        # Wait for the socket to reappear (launchd creates it).
        local waited=0
        while [[ ! -S "$PROD_SOCKET" ]] && [[ $waited -lt 5 ]]; do
            sleep 1
            ((waited++))
        done
        if [[ -S "$PROD_SOCKET" ]]; then
            echo "  Production agent socket restored: $PROD_SOCKET"
        else
            echo "  WARNING: production socket did not reappear after 5s."
            echo "  Manually reload with: launchctl load $PLIST"
        fi
    fi

    rm -f "$AGENT_LOG"

    echo
    echo "=== Results: $PASS passed, $FAIL failed ==="
    if [[ $FAIL -gt 0 ]]; then
        exit 1
    fi
    exit $exit_code
}
trap cleanup EXIT

# ── Helpers ──────────────────────────────────────────────────────────

assert_in_log() {
    local pattern="$1"
    local desc="$2"
    if grep -qF "$pattern" "$AGENT_LOG"; then
        echo "  PASS: $desc"
        ((PASS++))
    else
        echo "  FAIL: $desc"
        echo "        expected: $pattern"
        echo "        agent stderr:"
        sed 's/^/          /' "$AGENT_LOG"
        ((FAIL++))
    fi
}

assert_not_in_log() {
    local pattern="$1"
    local desc="$2"
    if ! grep -qF "$pattern" "$AGENT_LOG"; then
        echo "  PASS: $desc"
        ((PASS++))
    else
        echo "  FAIL: $desc"
        echo "        unexpected match: $pattern"
        ((FAIL++))
    fi
}

# start_agent: run a test agent on a temp socket, capture stderr.
# The managed-preference log lines are printed synchronously during
# startup, before the accept loop, so 1 second is sufficient.
start_agent() {
    rm -f "$TEST_SOCK" "$AGENT_LOG"
    "$BINARY" -l "$TEST_SOCK" >"$AGENT_LOG" 2>&1 &
    AGENT_PID=$!
    sleep 1
}

stop_agent() {
    if [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    AGENT_PID=""
    rm -f "$TEST_SOCK"
}

# ── Preflight ────────────────────────────────────────────────────────

echo "touchid-agent Track #2 §3 verification"
echo "======================================="
echo

# Build the binary if missing.
if [[ ! -x "$BINARY" ]]; then
    echo "Binary not found at $BINARY — building..."
    if ! make -C "$ROOT" build 2>&1; then
        echo "error: make build failed. See TROUBLESHOOTING in this script."
        exit 1
    fi
    echo
fi

echo "Binary:         $BINARY"
echo "Bundle ID:      $BUNDLE_ID"
echo "Production:     $PLIST"
echo "Test socket:    $TEST_SOCK"

# Auto-detect signing identity for Phase 2.
if ! $SKIP_PHASE2 && [[ -z "$SIGN_IDENTITY" ]]; then
    SIGN_IDENTITY=$(security find-identity -v 2>/dev/null \
        | grep "Developer ID Installer" \
        | head -1 \
        | sed 's/.*"\(.*\)"/\1/' || true)
    if [[ -n "$SIGN_IDENTITY" ]]; then
        echo "Signing ID:     $SIGN_IDENTITY (auto-detected)"
    else
        echo "Signing ID:     (none found — Phase 2 will be skipped)"
    fi
else
    if $SKIP_PHASE2; then
        echo "Phase 2:        skipped (--skip-phase2)"
    else
        echo "Signing ID:     $SIGN_IDENTITY"
    fi
fi
echo

# ── Stop production agent ────────────────────────────────────────────
#
# This ensures test `defaults write` values cannot leak into a live
# agent. The agent is restarted in the cleanup trap.

if [[ -f "$PLIST" ]] && launchctl list 2>/dev/null | grep -q "$BUNDLE_ID"; then
    echo "Stopping production agent (will restart on exit)..."
    launchctl unload "$PLIST" 2>/dev/null || true
    PROD_WAS_LOADED=true
    sleep 1
    echo
elif [[ -f "$PLIST" ]]; then
    # Plist exists but agent isn't loaded — still reload on exit to be safe.
    PROD_WAS_LOADED=true
fi

# ── Phase 0: baseline (no managed prefs) ─────────────────────────────

echo "=== Phase 0: baseline — no managed preferences ==="

# Ensure a clean slate in the user domain.
defaults delete "$BUNDLE_ID" audit_log_path 2>/dev/null || true
defaults delete "$BUNDLE_ID" peer_check 2>/dev/null || true
defaults delete "$BUNDLE_ID" rate_limit 2>/dev/null || true
defaults delete "$BUNDLE_ID" allowed_callers 2>/dev/null || true

start_agent
stop_agent

assert_not_in_log "Managed preference active" \
    "no override lines when preference domain is clean"
echo

# ── Phase 1: user-domain preferences (no sudo) ──────────────────────

echo "=== Phase 1: user-domain preferences ==="
echo "  Writing test values via \`defaults write\`..."

defaults write "$BUNDLE_ID" audit_log_path -string "/tmp/verify-audit.log"
defaults write "$BUNDLE_ID" peer_check -bool true
defaults write "$BUNDLE_ID" rate_limit -int 25
defaults write "$BUNDLE_ID" allowed_callers -string "/tmp/verify-callers.txt"
PHASE1_PREFS_SET=true

start_agent
stop_agent

assert_in_log 'Managed preference active: audit_log_path="/tmp/verify-audit.log"' \
    "audit_log_path override logged"
assert_in_log "Managed preference active: peer_check=true" \
    "peer_check override logged"
assert_in_log "Managed preference active: rate_limit=25" \
    "rate_limit override logged"
assert_in_log 'Managed preference active: allowed_callers="/tmp/verify-callers.txt"' \
    "allowed_callers override logged"

echo "  Cleaning up user-domain preferences..."
defaults delete "$BUNDLE_ID" audit_log_path 2>/dev/null || true
defaults delete "$BUNDLE_ID" peer_check 2>/dev/null || true
defaults delete "$BUNDLE_ID" rate_limit 2>/dev/null || true
defaults delete "$BUNDLE_ID" allowed_callers 2>/dev/null || true
PHASE1_PREFS_SET=false
echo

# ── Phase 2: signed .mobileconfig + profile install ─────────────────

if $SKIP_PHASE2 || [[ -z "$SIGN_IDENTITY" ]]; then
    echo "=== Phase 2: skipped ==="
    if [[ -z "$SIGN_IDENTITY" ]] && ! $SKIP_PHASE2; then
        echo "  No Developer ID Installer cert found in keychain."
        echo "  To run Phase 2, provide the identity as an argument:"
        echo "    $0 \"Developer ID Installer: Your Name (TEAMID)\""
        echo
        echo "  Available identities:"
        security find-identity -v 2>/dev/null | grep "Developer ID" | sed 's/^/    /' || echo "    (none)"
    fi
    echo
    exit 0
fi

echo "=== Phase 2: signed .mobileconfig + profile install ==="

VERSION="v0.0.0-verify"
PHASE2_MOBILECONFIG="$ROOT/dist/touchid-agent-${VERSION}.mobileconfig"

echo "  Building mobileconfig..."
if ! MACOS_INSTALLER_SIGN_IDENTITY="$SIGN_IDENTITY" \
    "$ROOT/scripts/build-mobileconfig.sh" "$VERSION" >/dev/null 2>&1; then
    echo "  FAIL: build-mobileconfig.sh failed"
    ((FAIL++))
    exit 0
fi

if [[ ! -f "$PHASE2_MOBILECONFIG" ]]; then
    echo "  FAIL: mobileconfig not found at $PHASE2_MOBILECONFIG"
    ((FAIL++))
    exit 0
fi

# 2a. Verify it's a signed CMS blob, not raw XML.
if head -c 5 "$PHASE2_MOBILECONFIG" | grep -q '<?xml'; then
    echo "  FAIL: mobileconfig is unsigned XML (signing likely failed)"
    ((FAIL++))
    exit 0
fi
echo "  PASS: mobileconfig is signed (binary CMS)"
((PASS++))

# 2b. Verify the CMS signature is valid.
if security cms -D -i "$PHASE2_MOBILECONFIG" >/dev/null 2>&1; then
    echo "  PASS: CMS signature validates"
    ((PASS++))
else
    echo "  FAIL: CMS signature validation failed"
    ((FAIL++))
    exit 0
fi

# 2c. Install the profile (needs sudo).
echo "  Installing profile (may prompt for sudo password)..."
if sudo profiles install -path "$PHASE2_MOBILECONFIG" 2>/dev/null; then
    PHASE2_PROFILE_INSTALLED=true
    echo "  PASS: profile installed"
    ((PASS++))
else
    echo "  FAIL: \`profiles install\` failed."
    echo "        On macOS 13+, manual profiles may need approval in"
    echo "        System Settings > Privacy & Security > Profiles."
    echo "        In production, MDM pushes the profile automatically."
    ((FAIL++))
    exit 0
fi

# 2d. Verify the agent picks up managed-domain values.
start_agent
stop_agent

assert_in_log "Managed preference active: audit_log_path" \
    "audit_log_path picked up from installed profile"
assert_in_log "Managed preference active: peer_check=true" \
    "peer_check picked up from installed profile"
assert_in_log "Managed preference active: rate_limit=30" \
    "rate_limit picked up from installed profile"

echo "  Removing profile..."
if sudo profiles remove -identifier "$PROFILE_ID" 2>/dev/null; then
    PHASE2_PROFILE_INSTALLED=false
    echo "  PASS: profile removed cleanly"
    ((PASS++))
else
    echo "  WARNING: profile removal failed — may need manual removal via"
    echo "           System Settings > Privacy & Security > Profiles"
fi
echo
