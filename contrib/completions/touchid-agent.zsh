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
        '-delete[Delete the key with the given label]:label:' \
        '-delete-all[Delete all managed keys]' \
        '-v[Enable verbose debug logging]' \
        '-version[Print version and exit]'
}

_touchid-agent "$@"
