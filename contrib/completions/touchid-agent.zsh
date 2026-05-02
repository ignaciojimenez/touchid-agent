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
        '-create[Create a new SSH key with the given label]:label:' \
        '-no-touch[Do not require Touch ID for this key]' \
        '-software[Use software-backed Keychain key instead of Secure Enclave]' \
        '-post-hook[Run command after key creation]:command:_command_names' \
        '-list[List all managed keys]' \
        '-delete[Delete the key with the given label]:label:' \
        '-delete-all[Delete all managed keys]'
}

_touchid-agent "$@"
