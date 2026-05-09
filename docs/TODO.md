# TODO

## Deferred

- [ ] Notarization stapling: not currently possible for flat Mach-O
      CLI binaries (stapler only supports `.app`/`.dmg`/`.pkg`). Could
      be revisited if Apple ships flat-binary stapling, or if the
      project ships a `.pkg` installer for managed deployments.
- [ ] Optional: submit to homebrew-core. Requires either a
      source-buildable formula (impossible: ad-hoc-signed binaries
      cannot reach the SEP) or a maintainer-shipped notarized bottle.
      Personal tap is simpler and correct for this use case.
