# TODO

## Unsorted

- [ ] Follow up on distribution roadmap
- [ ] Flag to disable features at build that could reduce attack surface (e.g. post-create hook, others?)
- [] Make documentation much more consistent and lean

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
- [ ] Add support for multi platform (Linux, Windows, etc?)
- [ ] Add support for other key types or secrets? (For example secrets 
      other than keys that could be used at runtime for other uses)

