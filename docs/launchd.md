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

### Quick setup (brew install)

```bash
touchid-agent -install-plist
```

This writes a socket-activation plist to
`~/Library/LaunchAgents/touchid-agent.plist`, creates the socket and
log directories, and loads the plist via launchctl. The socket is
placed at `~/Library/Caches/touchid-agent/agent.sock` (matching
yubikey-agent convention).

To enable per-signing audit logging at install time:

```bash
touchid-agent -install-plist -audit-log "$HOME/Library/Logs/touchid-agent-audit.log"
```

The command is idempotent: if a socket-activation plist is already in
place it's a no-op.

### Build-from-source setup

```bash
make install-launchd
launchctl load ~/Library/LaunchAgents/touchid-agent.plist
```

`make install-launchd` is the developer equivalent: it builds, signs,
and installs the binary, then writes a plist with paths set for your
system. Use `touchid-agent -install-plist` if the binary is already
on `PATH`.

### Migrating from the old `-l`-mode plist

If you have an existing plist that uses `-l PATH` with `RunAtLoad` and
`KeepAlive`, rewrite it in place:

```bash
touchid-agent -migrate-plist
```

This:

- backs up the existing plist to
  `~/Library/LaunchAgents/touchid-agent.plist.bak-pre-migrate-<timestamp>`,
- rewrites it to socket activation while preserving `-audit-log`,
  `-peer-check`, `-rate-limit`, `-allowed-callers`, and `-v` flags,
- unloads the old plist and loads the new one,
- and verifies the agent is reachable via `-status`.

Use `-dry-run` to print the proposed plist without writing, or
`-no-reload` to write the plist but skip the launchctl load.

The socket path stays the same (`~/Library/Caches/touchid-agent/agent.sock`),
so no changes are needed to `SSH_AUTH_SOCK` or `~/.ssh/config`.

The command is idempotent: if the plist is already socket-activated,
it's a no-op.

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
