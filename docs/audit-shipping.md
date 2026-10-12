# Shipping the audit log off the host

The audit log on its own is **tamper-evident**. Shipped off the host, it can be
**tamper-resistant**. This page says what each of those means here, and what
a receiving store must do for the second to be true.

## What the local log proves, and what it does not

Every signing event appends one JSON line to `~/Library/Logs/touchid-agent-audit.log`
(or the `-audit-log` path). Since v0.9.0 each record carries `seq` (monotonic)
and `prev` (SHA-256 of the previous line's exact bytes), and
`touchid-agent -verify-audit [-audit-log PATH]` walks the chain:

```
audit log OK: <path> — N record(s), M chain-protected, chain intact
audit log TAMPERED: <path> — chain broke at line L: <reason>
```

On the host, that detects a record that was **edited, reordered, inserted, or
removed from the middle**.

It does **not** stop someone who runs as the same user and can write the file:

- **Rewriting the whole file.** The chain starts from a fixed genesis value
  (64 zeros), so an attacker can rebuild any history from scratch and recompute
  a chain that verifies.
- **Cutting the tail.** Truncating the newest records leaves a valid prefix.
- **Silence.** Records the agent never wrote, because it was stopped or
  replaced, leave no gap to find.

So a clean `-verify-audit` on the host means "nobody edited the middle of this
file", not "this is everything that happened". Treat the local log as a
convenience and a tripwire, and the shipped copy as the record.

## What shipping has to provide

Ship each line as it is written, to a store the agent's user cannot change.
The guarantee holds only if all of these do:

1. **Bytes verbatim.** `prev` is the hash of the exact bytes of the previous
   line. A forwarder that parses and re-serialises JSON (reordering keys,
   changing whitespace or escaping) breaks the chain at the receiver. Ship
   lines as raw text, and parse a *copy* for indexing.
2. **Append-only, with credentials the host does not hold.** For example,
   object storage with a retention lock, or a log service the host can write to
   but not delete from. If the host's credentials can delete or overwrite
   shipped records, an attacker with the host has them too.
3. **Promptly.** What is shipped before a compromise is safe; what is still
   only local is not. The shipping interval is the window an attacker can
   rewrite.
4. **Checked on arrival**, per host:
   - `seq` must rise by exactly 1. A gap means records were removed or held
     back. A *drop* in `seq` means the file was replaced, the strongest signal
     of all.
   - `prev` must match the hash of the last line received.
   - Periodically, run `touchid-agent -verify-audit -audit-log <received copy>`
     against the receiver's copy.
5. **Alerted when it goes quiet**, if the host normally signs every day.
   Stopping the agent or its forwarder is the cheapest way to hide.

Any file-tailing forwarder can do the shipping (the macOS-native options and
the usual log agents all can). This page deliberately names no configuration:
the requirements above are what to check, whichever tool is used.

## Decided, so not to be re-proposed

- **Forward-secure sealing is deferred.** Issue #19's Phase 2 (an evolving MAC
  key, with the verifier kept off the host) would protect the *local* log's
  past after a compromise. Shipping already gives that, more simply, for anyone
  who ships. Revisit only for hosts that cannot ship.
- **The macOS unified log is rejected as the audit store.** It is a lossy
  diagnostics system, rate-limited and evicted by policy, not a record you can
  prove complete.
