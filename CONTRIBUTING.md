# Contributing

## Shell Completions

When adding, removing, or renaming CLI flags in `main.go`, update the shell
completion scripts to stay in sync:

- `contrib/completions/touchid-agent.bash` — update `_touchid_agent_flags` and
  the `case` statement for flags that take values.
- `contrib/completions/touchid-agent.zsh` — update the `_arguments` list.

Flags that accept a value (e.g. `-create NAME`) need special handling in both
scripts: bash needs a `case` entry to suppress file completion, zsh needs a
`:description:` suffix on the argument spec.
