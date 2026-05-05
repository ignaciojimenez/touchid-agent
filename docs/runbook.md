# Operational runbook

This file documents on-call recovery procedures for touchid-agent. It is
aimed at someone whose SSH workflow has just broken and who needs to fix
it without becoming an expert on the agent.

## Quick triage

```bash
# Is the agent running?
launchctl list | grep touchid-agent
ls -l "$HOME/Library/Caches/touchid-agent/agent.sock"

# Does ssh-add see the keys?
SSH_AUTH_SOCK="$HOME/Library/Caches/touchid-agent/agent.sock" ssh-add -L

# Is the binary signed and notarized?
codesign -dv --verbose=4 "$(which touchid-agent)" 2>&1 | grep -E '^(Authority|TeamIdentifier|Timestamp|Notarization)'

# Recent agent log lines
tail -50 "$HOME/Library/Logs/touchid-agent.log" 2>/dev/null
```

If `ssh-add -L` returns the key list and the socket exists, the agent is
healthy; the fault is somewhere else (SSH config, network, remote host).

## Touch ID lockout

**Symptom.** Signing fails with the error:

> Touch ID is locked out after too many failed attempts; unlock your Mac
> with your password to recover Touch ID, then retry — the key on disk
> is valid

This is `LAError -8` (`biometryLockout`). The SEP refuses biometric
authentication after enough consecutive failures (Apple does not
publish the exact threshold; it is typically five).

### Recovery (user)

1. Lock the screen (Control-Command-Q).
2. Unlock with your **password** (not Touch ID). This re-arms the
   biometric subsystem on the next successful auth.
3. Retry the SSH operation. The Touch ID prompt should reappear.

If lockout persists:

- Reboot the Mac. SEP biometry counters reset on cold boot.
- Verify Touch ID is still enrolled: System Settings → Touch ID & Password.
  If a finger has been removed (e.g. after a security incident), re-enroll.

### Detection (operations)

There is no platform-level event for Touch ID lockout. Indirect signals:

- `touchid-agent.log` lines containing `biometryLockout` or `LAError -8`.
- A burst of `signing failed` lines around the same timestamp.
- User reports of repeated Touch ID prompts that do not accept a touch.

If you operate the audit log (`-audit-log` flag), filter for
`"event":"sign"` records with `"success":false` and `"reason":` matching
biometry failures.

### Break-glass: a `-no-touch` key

Per-operation Touch ID is the security default. If your team needs a
break-glass path so a locked-out engineer can still authenticate during
an incident, create a second key on each host:

```bash
touchid-agent -create breakglass -no-touch
```

The break-glass key:

- Lives in the same SEP, so it is still non-extractable.
- Does not require biometry; any process the engineer is running can
  sign with it.
- Should be **registered only with limited-blast-radius hosts**, e.g.
  break-glass bastion, runbook git repo, on-call paging webhook.
  Do **not** add it to production SSH or to GitHub for code-signing.

Document the break-glass key's existence and scope in your access
register so it is not mistaken for an unauthorized key.

## Other known LAError outcomes

| Error                                | What happened                            | Recovery |
|--------------------------------------|------------------------------------------|----------|
| `userCancel` (LAError -2)            | User dismissed the Touch ID prompt       | Re-run the SSH command and confirm the prompt. |
| `biometryNotAvailable` (LAError -6)  | Mac has no Touch ID hardware             | Use a `-no-touch` key, or run on a Touch-ID-equipped Mac. |
| `biometryNotEnrolled` (LAError -7)   | No fingerprints enrolled                 | System Settings → Touch ID & Password → Add Fingerprint. |
| `biometryLockout` (LAError -8)       | Too many failed attempts                 | See above. |
| `passcodeNotSet` (LAError -4)        | No login password                        | Set a password (Touch ID is gated behind a password). |

`classifySignError()` in `main.go` maps each of these to an actionable
message before the agent surfaces them.

## Agent crash or socket missing

```bash
# Reload the launchd job
launchctl unload "$HOME/Library/LaunchAgents/touchid-agent.plist"
launchctl load   "$HOME/Library/LaunchAgents/touchid-agent.plist"

# Verify socket reappears
ls -l "$HOME/Library/Caches/touchid-agent/agent.sock"
```

If launchd reports a non-zero exit code in `touchid-agent.log`, check:

- **`Failed to listen on UNIX socket`** — usually a stale socket file
  the agent did not clean up. The agent removes the file on startup, but
  if a previous run was killed with `SIGKILL` the file remains. Delete
  it manually and reload.
- **`could not access SE`** — almost always a code-signing problem.
  Re-run `codesign -dv` and confirm the Authority chain ends at Apple
  Root CA. An ad-hoc-signed binary cannot reach the SEP.

## Lost or unreachable key

SE keys are device-bound. There is no recovery path if:

- The Mac is wiped, replaced, or the user account is recreated.
- `~/.touchid-agent/keys/` is deleted.

In all these cases, generate a new key and re-register it on the remote
side (`~/.ssh/authorized_keys`, GitHub, GitLab, signing config, etc.).

For corporate deployments, ensure your access register can revoke the
old public key promptly when an endpoint is decommissioned.

## Reporting a bug

Capture the following before opening an issue:

```bash
touchid-agent -version
sw_vers
codesign -dv --verbose=4 "$(which touchid-agent)" 2>&1 | head -20
tail -100 "$HOME/Library/Logs/touchid-agent.log"
```

Redact any key labels you consider sensitive before sharing.
