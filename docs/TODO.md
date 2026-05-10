# TODO

## Unsorted

- [ ] Distribution roadmap Track #2 §3 — configuration profile
      (`.mobileconfig`) + Managed Preferences read path in the agent.
      Last remaining piece for the Munki pilot. See
      `docs/distribution-roadmap.md`.
- [ ] Distribution roadmap Track #2 §4 — `docs/deployment.md` after
      the first Munki pilot run.
- [ ] Distribution roadmap Track #3 — enrollment + inventory. v1
      target is webhook contract + LDAP-keyserver adapter
      (`contrib/hooks/custom-api-upload.sh` is the shape).
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
- [ ] Add support for multi platform (Linux, Windows, etc?)
- [ ] Add support for other key types or secrets? (For example secrets
      other than keys that could be used at runtime for other uses)

## Done

- [x] **v0.4.0** — Distribution roadmap Track #2 §1 + §2: signed,
      notarized `.pkg` installer with system-wide bootstrap
      LaunchAgent + `-ensure-user-plist` subcommand.
- [x] **v0.4.0** — Notarization stapling: now stapled for the `.pkg`
      via `xcrun stapler staple` in `scripts/build-pkg.sh`. Flat
      Mach-O CLI binaries still cannot be stapled (Apple limitation).

