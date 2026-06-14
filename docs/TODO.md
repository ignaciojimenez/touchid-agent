# TODO

## Next

- [ ] Tamper-evident / forward-secure audit logging — issue
      [#19](https://github.com/ignaciojimenez/touchid-agent/issues/19).
      Start with Phase 1 (per-record hash chain + `-verify-audit`); then
      forward-secure sealing (journald-FSS style); then off-host shipping.
- [ ] Distribution roadmap Track #2 §4 — `docs/deployment.md` after the
      first Munki pilot run.
- [ ] Distribution roadmap Track #3 — enrollment + inventory. v1 target
      is webhook contract + LDAP-keyserver adapter
      (`contrib/hooks/custom-api-upload.sh` is the shape).
- [ ] Build-time flag to drop optional features (e.g. post-create hooks)
      to shrink attack surface for hardened fleet builds.

## Deferred

- [ ] Key fingerprint cache: `signFor()` does an O(n) list + linear scan
      per request. A fingerprint-indexed map invalidated on store
      mutations is cleaner. Not a problem at current key counts (< 10).
- [ ] PID file / flock for stale-socket detection in `-l` mode. Less
      critical now that `-launchd` eliminates this for launchd users.
- [ ] Multi-platform support (Linux, Windows, …).
- [ ] Other key types / runtime secrets beyond SSH keys.

## Done

- [x] **v0.8.0** — Trustworthy caller verification (issue #17): audit-token
      resolution + code-signing identity, default Apple-only by signature,
      `team-id:`/`signing-id:`/`cdhash:`/`path:` rules, MDM/root-anchored;
      `-require-hardened-callers`; per-key caller binding (#20).
- [x] **v0.7.0** — Peer verification on by default (#9, opt out
      `-no-peer-check`); audit logging on by default to
      `~/Library/Logs/touchid-agent-audit.log` (#10).
- [x] **v0.6.0** — Signing-policy hardening (keyfile metadata tamper
      checks) + dependency bumps.
- [x] **v0.4.0** — Distribution roadmap Track #2 §1–§3: signed/notarized
      `.pkg` + bootstrap LaunchAgent + `-ensure-user-plist`; signed
      configuration profile + Managed Preferences read path; notarization
      stapling for the `.pkg`.
- [x] Documentation consistency pass — unified the THREAT_MODEL risk
      taxonomy and refreshed docs for the v0.6–v0.8 changes.
