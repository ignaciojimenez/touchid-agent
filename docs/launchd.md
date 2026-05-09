# Running as a launchd service

## Socket activation (recommended)

With socket activation, launchd creates and owns the Unix socket. The
agent starts on first connection and exits after 10 minutes of
inactivity. launchd restarts it automatically on the next connection.

Benefits over the traditional always-running mode:

- **Zero idle footprint.** The agent is not running when no SSH
  operations are in progress.
- **No stale sockets.** launchd owns the socket; it persists across
  agent restarts and crashes.
- **Faster first-connection latency.** The socket is available
  immediately after login, before the agent process starts.

### Quick setup

```bash
make install-launchd
launchctl load ~/Library/LaunchAgents/touchid-agent.plist
```

This generates a plist with correct paths for your system and writes
it to `~/Library/LaunchAgents/touchid-agent.plist`.

The socket is placed at `~/Library/Caches/touchid-agent/agent.sock`
(matching yubikey-agent convention).

### Manual setup

Copy the template and replace placeholders:

```bash
cp contrib/plist/touchid-agent.plist ~/Library/LaunchAgents/
sed -i '' -e "s|__BINARY__|$(which touchid-agent)|g" \
          -e "s|__HOME__|$HOME|g" \
    ~/Library/LaunchAgents/touchid-agent.plist
launchctl load ~/Library/LaunchAgents/touchid-agent.plist
```

### Migrating from the old plist (RunAtLoad + KeepAlive)

If you have an existing plist that uses `-l PATH` with `RunAtLoad` and
`KeepAlive`, update it to use socket activation:

```bash
launchctl unload ~/Library/LaunchAgents/touchid-agent.plist
make install-launchd
launchctl load ~/Library/LaunchAgents/touchid-agent.plist
```

The socket path stays the same (`~/Library/Caches/touchid-agent/agent.sock`),
so no changes are needed to `SSH_AUTH_SOCK` or `~/.ssh/config`.

The old `-l PATH` mode still works if you prefer an always-running
agent. See "Traditional mode" below.

## Traditional mode (-l)

For manual or non-launchd use, the agent can manage its own socket:

```bash
touchid-agent -l ~/Library/Caches/touchid-agent/agent.sock
```

Or with a launchd plist that uses `RunAtLoad` + `KeepAlive`:

```xml
<key>ProgramArguments</key>
<array>
  <string>/usr/local/bin/touchid-agent</string>
  <string>-l</string>
  <string>/Users/you/Library/Caches/touchid-agent/agent.sock</string>
</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
```

## Pointing SSH at the agent

Add to `~/.zshrc`:

```bash
export SSH_AUTH_SOCK="$HOME/Library/Caches/touchid-agent/agent.sock"
```

Or use per-host configuration in `~/.ssh/config`:

```
Host *
    IdentityAgent ~/Library/Caches/touchid-agent/agent.sock
```

## Audit logging

The agent can record one JSON-lines record per signing operation when
started with `-audit-log PATH`. This works with both `-launchd` and
`-l` modes:

```xml
<key>ProgramArguments</key>
<array>
  <string>__BINARY__</string>
  <string>-launchd</string>
  <string>-audit-log</string>
  <string>__HOME__/Library/Logs/touchid-agent-audit.log</string>
</array>
```

Each record looks like:

```json
{"ts":"2026-05-05T10:00:00Z","event":"sign","label":"ssh","success":true,"peer_pid":1234,"peer_uid":501}
```

The audit log is opened with mode 0600. For SOC 2 / corporate
compliance, ship this file to your SIEM (rsyslog, Vector, FluentBit
file source). It is independent of the `-v` debug log on stderr.

## Unloading

```bash
launchctl unload ~/Library/LaunchAgents/touchid-agent.plist
```
