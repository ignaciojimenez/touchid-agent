# Running as a launchd service

Copy the plist and load it:

```bash
cp contrib/plist/touchid-agent.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/touchid-agent.plist
```

The service runs at login, restarts on failure, and logs to
`/tmp/.touchid-agent.log`.

To point SSH at the agent, add to `~/.zshrc`:

```bash
export SSH_AUTH_SOCK="/tmp/.touchid-agent.sock"
```

Or use per-host configuration in `~/.ssh/config`:

```
Host github.com
    IdentityAgent /tmp/.touchid-agent.sock
```
