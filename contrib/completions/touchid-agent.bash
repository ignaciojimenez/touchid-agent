# Bash completion for touchid-agent
#
# Install:
#   cp touchid-agent.bash /usr/local/etc/bash_completion.d/touchid-agent
#   # or: source touchid-agent.bash
#
# MAINTENANCE: When adding or removing flags in main.go, update the
# _touchid_agent_flags list below to keep completions in sync.

_touchid_agent() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # All top-level flags.
    local _touchid_agent_flags="-l -audit-log -peer-check -rate-limit -allowed-callers -create -no-touch -post-hook -list -delete -delete-all -v -version"

    case "${prev}" in
        -l|-audit-log|-create|-delete|-post-hook|-rate-limit|-allowed-callers)
            # These flags expect a value; fall through to default completion.
            return 0
            ;;
    esac

    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${_touchid_agent_flags}" -- "${cur}") )
        return 0
    fi
}

complete -F _touchid_agent touchid-agent
