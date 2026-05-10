#compdef touchid-agent
#
# Zsh completion for touchid-agent
#
# Install:
#   cp touchid-agent.zsh /usr/local/share/zsh/site-functions/_touchid-agent
#   # or: fpath+=(/path/to/contrib/completions) && compinit
#
# MAINTENANCE: When adding or removing flags in main.go, update the
# arguments list below to keep completions in sync.

_touchid-agent() {
    _arguments -s \
        '-l[Run the agent, listening on the UNIX socket at PATH]:socket path:_files' \
        '-launchd[Run the agent using launchd socket activation]' \
        '-audit-log[Append a JSON-lines record per signing operation]:audit log path:_files' \
        '-peer-check[Verify peer binary against allowlist for no-touch keys]' \
        '-rate-limit[Max signing operations per key per minute (ceiling: 120)]:limit:' \
        '-allowed-callers[Path to file listing additional allowed caller binaries]:file:_files' \
        '-create[Create a new SSH key with the given label]:label:' \
        '-no-touch[Do not require Touch ID for this key]' \
        '-post-hook[Run command after key creation]:command:_command_names' \
        '-list[List all managed keys]' \
        '-json[Output list as JSON array]' \
        '-status[Check if the agent at PATH is healthy]:socket path:_files' \
        '-delete[Delete the key with the given label]:label:' \
        '-delete-all[Delete all managed keys]' \
        '-install-plist[Write launchd plist (socket activation) and load it]' \
        '-migrate-plist[Rewrite an existing -l-mode plist to socket activation]' \
        '-plist[Plist path (defaults to ~/Library/LaunchAgents/touchid-agent.plist)]:plist path:_files' \
        '-dry-run[migrate-plist: print proposed plist without writing]' \
        '-no-reload[install-plist/migrate-plist: skip launchctl load/unload]' \
        '-v[Enable verbose debug logging]' \
        '-version[Print version and exit]'
}

_touchid-agent "$@"
