# Running as a launchd service

## Recommended: make install-launchd

```bash
make install-launchd
launchctl load ~/Library/LaunchAgents/touchid-agent.plist
```

This generates a plist with correct paths for your system (binary
location, home directory, socket and log paths) and writes it to
`~/Library/LaunchAgents/touchid-agent.plist`.

The socket is placed at `~/Library/Caches/touchid-agent/agent.sock`
(a per-user location, matching yubikey-agent convention).

## Manual setup

If you prefer to configure the plist yourself, copy the template and
replace the `__BINARY__` and `__HOME__` placeholders:

```bash
cp contrib/plist/touchid-agent.plist ~/Library/LaunchAgents/
sed -i '' -e "s|__BINARY__|$(which touchid-agent)|g" \
          -e "s|__HOME__|$HOME|g" \
    ~/Library/LaunchAgents/touchid-agent.plist
launchctl load ~/Library/LaunchAgents/touchid-agent.plist
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
started with `-audit-log PATH`:

```xml
<key>ProgramArguments</key>
<array>
  <string>__BINARY__</string>
  <string>-l</string>
  <string>__HOME__/Library/Caches/touchid-agent/agent.sock</string>
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
