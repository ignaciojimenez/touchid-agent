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

## Unloading

```bash
launchctl unload ~/Library/LaunchAgents/touchid-agent.plist
```
