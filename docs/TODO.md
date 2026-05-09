# TODO

## Deferred

- [ ] Key fingerprint cache: `signFor()` does O(n) list + linear scan
      per signing request. A fingerprint-indexed map invalidated on
      store mutations would be cleaner. Not a performance issue at
      current key counts (< 10), but better architecture.
- [ ] PID file / flock for stale socket detection in `-l` mode. Would
      let tooling distinguish "stale socket" from "another instance
      running." Less critical now that `-launchd` eliminates this for
      launchd users.
- [ ] Notarization stapling: not currently possible for flat Mach-O
      CLI binaries (stapler only supports `.app`/`.dmg`/`.pkg`). Could
      be revisited if Apple ships flat-binary stapling, or if the
      project ships a `.pkg` installer for managed deployments.
- [ ] Optional: submit to homebrew-core. Requires either a
      source-buildable formula (impossible: ad-hoc-signed binaries
      cannot reach the SEP) or a maintainer-shipped notarized bottle.
      Personal tap is simpler and correct for this use case.
