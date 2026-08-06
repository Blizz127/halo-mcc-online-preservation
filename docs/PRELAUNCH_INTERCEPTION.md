# P0-C2D pre-launch interception tooling

Status: **P0-C2D0-R2 corrected the live-contract gaps, and the separately authorized P0-C2D live
single-host blind-relay rung completed as `A. BLIND RELAY PASS`. The follow-on P0-C2D1 TLS/SNI/ALPN
observation rung halted at its starting gate before any live action; P0-C2D1-R0 corrects the
observer bounds that caused the halt. A separate Meta Muse Spark 1.2 read-only audit of P0-C2D0
remains pending.**

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
  Its runtime bounds were reconciled with measured live behaviour in **P0-C2D1-R0**, and every run
  now records why it ended.
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

## Live result: P0-C2D

`evidence/p0c2d_live_blind_relay/` records the first accepted live use of this tooling. With a
pre-launch exact-host redirect, MCC completed cached Microsoft/Xbox identity, made one connection
through the opaque relay, exchanged 4,728 client-to-upstream and 29,226 upstream-to-client encrypted
bytes, and reached the main menu without a certificate or service error. The redirect affected no
protected identity host. Exact `/etc/hosts` rollback completed fifteen seconds before relay expiry,
and a separate normal post-rollback launch succeeded.

The result proves only that this selected host can traverse the pre-launch blind relay without
breaking the observed cached-identity/main-menu path. TLS was not terminated; no payload, request,
response, certificate body, or account identifier was inspected or persisted. CA acceptance,
pinning, plaintext schema, and settings authority remain unresolved.

## Live observer bounds — P0-C2D1-R0

The relay's bounds were reconciled with measured launch behaviour in R2. The observer's were not,
and the authorized P0-C2D1 live rung halted at its starting gate because of it. Full detail in
`evidence/p0c2d1r0_observer_bounds_correction/REPORT.md` (`E-P0C2D1R0-002`, `E-P0C2D1R0-004`).

The observer must be listening **before** the redirect is installed, so its runtime has to cover the
`/etc/hosts` install, the whole scope verification, and then the measured 75 s from scope
verification to the settings connection arriving at the listener (`E-P0C2D-004`) — on top of the
72 s launch-to-title-service delay that interval already contains (`E-P0C1-003`). The old
`MAX_SECONDS = 120.0` left roughly 20–35 s of margin, which any Steam cold start consumes.

| Setting | Recommended live value | Reason |
|---|---|---|
| `--seconds` | 240 | Redirect install + scope verify + Steam start + launch-to-title-service, with margin, inside the hard maximum |
| `--max-connections` | 8 | Reconnect headroom — and MCC's retry after a handshake is part of how a rejected certificate is told apart from an accepted one |

The hard maximum is now `prelaunch_relay.MAX_SECONDS` (**300 s**) rather than a second, separate
number: one bound across both live interception tools. It was raised to an already-accepted value,
not to a new one. A longer experiment still needs a new rung.

**Dead-observer hazard.** The observer has no lingering mode — it stops accepting at its connection
cap — so with the old default cap of 1 it exited after the first connection while the redirect was
still installed, and MCC's retry would have met a refused connection. Two controls bound this, and
they are complementary:

1. *Code.* The cap defaults to 8, and every run records `exit_reason` (`total_deadline` or
   `connection_cap_reached`) alongside `observation_count`, `total_timeout_seconds`, and
   `elapsed_seconds`, in log format `p0c2d1r0-tls-observer-v2`. Without that, an observer that
   expired before MCC arrived is indistinguishable from one that stayed up and proved MCC never
   came — the first is a tooling failure, the second is a claim about MCC.
2. *Runbook.* Roll the redirect back **before** observer expiry, exactly as for the relay.

**Preflight step ordering.** `--stage tls-observer` requires `--cert` and `--key`, and its Wine
CA-absence check is all-or-none on `--prefix`, `--proton-wine`, and `--ca-thumbprint`. A live rung
must therefore generate the exact-host certificate into repository-external scratch **before**
running the preflight — that writes only mode-`0600` material and changes no system state — and then
supply all five arguments. This is a runbook ordering requirement, not a tool defect
(`E-P0C2D1R0-003`).

## Phase boundary

P0-C2D0-R2 establishes only that the preflight, probe, and relay bounds now match the live rung's
authorized state and scope, under synthetic validation. It establishes no MCC request, response,
TLS acceptance or pinning verdict, settings manifest, endpoint authority, or production forwarding
behaviour, and it changes no architecture hypothesis.

**P0-C2D is complete. P0-C2D1 was authorized, halted at its starting gate before any live action,
and is not completed. P0-C2E is not started.** The P0-C2D live result supports re-running the
exact-host TLS/SNI/ALPN observation rung now that the observer's bounds cover the measured timeline,
but neither that result nor P0-C2D1-R0 authorizes the run, any CA generation, any Wine trust
installation, or any redirect. The corrected tooling still awaits the separate Meta Muse Spark 1.2
read-only audit noted above.
