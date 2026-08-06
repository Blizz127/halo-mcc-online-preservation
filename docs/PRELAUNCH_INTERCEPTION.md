# P0-C2D pre-launch interception tooling

Status: **P0-C2D0-R2 corrects live-contract gaps found when the first P0-C2D live attempt halted at
its starting gate. The live experiment did not begin, no live classification is possible, and no
system or client state was changed. A separate Meta Muse Spark 1.2 read-only audit remains pending.**

R1 corrected every blocker from the Codex Sol adversarial audit (`C. REJECT — RELAY SAFETY FAILURE`
on the first local candidate). R2 corrects a different class of problem: the tooling obeyed its
synthetic contract but could not gate the live rung it was written for.

## Why the first live attempt halted

Four findings; three are structural tooling gaps and one is an operator precondition. Full detail in
`evidence/p0c2d0r2_live_preflight_correction/REPORT.md` (`E-P0C2D0R2-001`).

| Finding | Kind |
|---|---|
| Preflight demanded the repository be exactly **one commit ahead** of `origin/main`; the authorized live state is 0 ahead / 0 behind | Structural |
| Preflight **unconditionally required a certificate and key**, though the blind-relay rung forbids generating or installing a CA | Structural |
| **No upstream TLS probe existed**; the only client-side TLS tool sends an HTTP request and records none of the required fields | Structural (missing tool) |
| **Steam was running** | Operator precondition |

The accepted P0-C2D0 audit did not catch the three structural gaps. It was adversarial against the
tools' *synthetic* contract and every finding it raised was real, but it did not test them against
the live rung's authorized state and scope — and the committed suite asserted the same wrong
expectations the code held. A suite that encodes an assumption cannot detect it.

## Safety boundary

- `prelaunch_relay.py` is the only ready forwarding component. Its CLI accepts exactly
  `127.0.0.77:443`, `settings.svc.halowaypoint.com`, a numeric upstream IPv4 address, bounded
  runtime/connection counts, and explicit log/PID/ready paths. It performs no DNS and never
  terminates TLS or persists payload bytes. It binds/listens before creating artifacts, publishes
  atomic PID/ready controls with a per-run identifier, removes only recognized stale controls,
  preserves replaced/unrelated paths, bounds every write, and closes/joins workers by deadline.
  Its upstream contract now disqualifies unspecified, loopback, link-local, **multicast**, reserved,
  and private addresses explicitly — `is_global` alone admits IPv4 multicast.
- `upstream_probe.py` validates one literal candidate before any redirect exists. It performs no
  DNS, requires `CERT_REQUIRED` with hostname verification and exact SNI, advertises ALPN, **sends no
  application byte**, records metadata only, and never writes a certificate body, DER, or PEM. The
  hostname is a constant with no CLI flag; documentation, benchmarking, shared-space, multicast,
  reserved, private, loopback, link-local, and IPv6 candidates are refused before a socket exists.
- `host_redirect.py` changes nothing itself. It rejects duplicates, checks IPv4 and IPv6, requires
  all six identity hosts to resolve away from the observer, and records the original hash, inode,
  size, exact inserted line, sentinel, host, and address. Rollback removes exactly one authorized
  line in memory, proves every remaining byte equals the recorded pre-state, refuses concurrent or
  ambiguous changes, guards the in-place write with current hash/inode, and verifies final
  hash/size/inode plus sentinel absence. Its emergency command also removes only that exact line.
- `local_ca.py` writes only outside the repository through a non-symlink directory, allows at most
  two days, and permits a real-host certificate only for `settings.svc.halowaypoint.com` with a
  critical exact-name constraint. `wine_trust.py` validates a 40-hex thumbprint, requires exact
  post-install presence, and treats delete failure, query failure, or continued presence as a
  removal failure. **Neither is used by the blind-relay stage.**
- `p0c2d_preflight.py` is read-only and **stage-aware**. It checks configurable branch/HEAD/remote
  tip and separately computed ahead/behind counts, clean tracked and nonignored-untracked state,
  proxy variables, listener absence through `/proc/net/tcp`, project/capture/MCC processes, Steam
  policy, hosts sentinels, manual selected-host entries, selected-host IPv4/IPv6, all six identity
  hosts, required tools, and repository-external non-symlink scratch/output paths. It never binds,
  edits, starts Wine, or terminates anything.
- `tls_observer.py` is bounded, records TLS/SNI/ALPN and value-free HTTP/1.1 metadata, never forwards,
  and never persists peer addresses, header values, query values, opaque path/host identifiers, or
  bodies. Production SNI must match the selected hostname; missing/mismatched SNI is closed before
  application parsing. `h2` is explicitly `unsupported_protocol` and is never parsed. Certificate
  acceptance requires post-handshake application data. It shares the relay's owned-control lifecycle.
- `reverse_proxy.py` is explicitly **NOT READY**. Its inherited runnable forwarder was removed because
  safe streaming HTTP/1.1 framing, persistent exchanges, upgrades/trailers/informational responses,
  and TLS half-close/deadline behavior are not proven.

Synthetic tests use only loopback addresses, high unprivileged ports, and reserved `.invalid`/`.test`
names. The production CLI paths are not exercised by the test suite, and no test contacts a
production service.

## Preflight stages

`--stage` is required and never inferred from which arguments happen to be present.

| Stage | Certificate material | Wine inspection |
|---|---|---|
| `blind-relay` | Must **not** be supplied; supplying any is a failure. No certificate file is opened | None |
| `tls-observer` | `--cert` and `--key` required | Optional, all-or-none on `--prefix`, `--proton-wine`, `--ca-thumbprint` |

Git expectations are explicit: `--expected-ahead` and `--expected-behind` default to `0`, so the
pushed synchronized state gates cleanly, and a local-only review state is expressed as
`--expected-ahead 1` rather than assumed. Malformed or failing Git output fails closed. No commit
hash is hardcoded.

## Live relay bounds

The hard maximum is unchanged at **300 s**. A longer experiment needs a new rung, not a bigger
number.

| Setting | Recommended live value | Reason |
|---|---|---|
| `--seconds` | 240 | Steam start + the 72 s launch-to-title-service delay measured in P0-C1 (`E-P0C1-003`) + operator latency, with margin |
| `--idle-seconds` | 240 | Equal to total. A healthy settings connection is expected to sit quiet; tearing it down mid-session would corrupt the observation |
| `--max-connections` | 8 | Reconnect headroom, so open/close/reopen does not exhaust the cap under a live redirect |

**Dead-relay hazard, and the two controls that bound it.** A relay that exits while the redirect is
still installed leaves the selected host pointing at nothing.

1. *Code.* The production CLI path lingers to its deadline instead of returning when the connection
   cap is reached. Over-cap connections are closed immediately and recorded as `ConnectionCapReached`
   rather than silently refused. Every run records an `exit_reason` — `total_deadline`,
   `connection_cap_reached`, or `connection_cap_reached_lingering` — so a cap-bounded run is never
   read as a complete one.
2. *Runbook.* Rollback must still be performed **before** relay expiry, not after. The ready file
   disappearing is the liveness signal; if it is gone, roll the redirect back before anything else.

These are complementary, not alternatives.

## Phase boundary

P0-C2D0-R2 establishes only that the preflight, probe, and relay bounds now match the live rung's
authorized state and scope, under synthetic validation. It establishes no MCC request, response,
TLS acceptance or pinning verdict, settings manifest, endpoint authority, or production forwarding
behaviour, and it changes no architecture hypothesis.

**P0-C2D is not started. P0-C2E is not started.** The corrected tooling is ready for a bounded
independent read-only audit, which should treat the live rung's authorized state and scope — not only
the synthetic contract — as part of what it checks.
