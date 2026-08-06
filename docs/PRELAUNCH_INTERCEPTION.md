# P0-C2D pre-launch interception tooling

Status: **P0-C2D0-R2 corrected the live-contract gaps, and the separately authorized P0-C2D live
single-host blind-relay rung completed as `A. BLIND RELAY PASS`. The follow-on P0-C2D1 TLS/SNI/ALPN
observation first halted before live action; P0-C2D1-R0 corrected its bounds. A later live attempt
ended `E. SNI / OBSERVER CONTRACT FAILURE` because setup consumed the observer window and launch
was issued after expiry. P0-C2D1-R1 added a fail-closed remaining-runtime gate and explicit direct-
baseline contract. Retry 1 passed that gate and completed as `A. TLS CERTIFICATE ACCEPTED`: eight
exact-SNI TLS 1.2 handshakes carried post-handshake application data. No upstream response or server
emulation occurred. A separate Meta Muse Spark 1.2 read-only audit of P0-C2D0 remains pending.**

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
  now records why it ended. **P0-C2D1-R1** adds owned run-start/deadline metadata and a read-only
  launch-window decision that validates PID/run identity, observer liveness, the exact listener,
  and remaining monotonic runtime immediately before a live client launch.
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

## Live attempt result — P0-C2D1

The later authorized live attempt is recorded in `evidence/p0c2d1_tls_observation/`
(`E-P0C2D1-001` through `E-P0C2D1-006`). Exact certificate constraints, prefix-only trust, observer
readiness, and one-host redirect scope passed. The observer started at `15:58:38-05:00` with the
recommended 240-second/eight-connection bounds, but the redirect was not confirmed installed until
`16:02:24` and scope verification began at `16:02:36`, seconds before the `16:02:38` deadline.
Steam launch was then issued at `16:02:43`, after the listener had closed.

The observer's fixed-schema result was `exit_reason: total_deadline`, `elapsed_seconds: 240.103`, and
`observation_count: 0`. This is **`E. SNI / OBSERVER CONTRACT FAILURE`**, specifically a failed
lifecycle/runbook window. It is not `D. OBSERVER NOT CONTACTED`: MCC never received a valid bounded
window in which to contact the observer. No SNI, TLS version, cipher, ALPN, application data,
certificate verdict, protocol result, or pinning verdict was observed.

The exact hash- and inode-guarded hosts rollback restored the original bytes, SHA-256, size, mode,
and inode. Resolver state and all protected-host resolutions returned to normal. The exact CA
thumbprint was removed from the MCC Proton-Wine Root store and independently verified absent; all
temporary certificate and key files were deleted. A separate normal post-rollback launch completed
identity and reached the main menu without a certificate/service error, followed by verified process
shutdown.

The failed sequence adds a stricter operational gate for any separately authorized retry: prepare
and validate every non-observer prerequisite and the exact install/rollback commands before starting
the observer, and refuse redirect or launch unless the remaining bounded runtime still covers the
measured live interval. The current result does not justify application-layer passthrough work.

## Remaining-runtime and baseline correction — P0-C2D1-R1

R1 is a tooling/runbook correction only. It preserves commit `ed9e323` as the historical partial
live P0-C2D1 attempt: outcome E, observer expired before live client contact, no TLS trust result,
and complete system restoration. R1 observed no new MCC behavior and does not change an architecture
hypothesis.

The named launch threshold is
`MIN_LIVE_LAUNCH_REMAINING_SECONDS = 150`. It is twice the measured 75-second
redirect-verify-to-connect interval (`E-P0C2D-004`), leaving a second measured interval as operating
margin rather than using the 72-second launch-to-title-service measurement as a razor-thin cutoff.
The threshold remains compatible with the recommended 240-second observer runtime.

Every observer PID and ready control now owns the same run identifier, process identifier,
boot-monotonic start/deadline, wall-clock audit timestamp, and configured timeout. Immediately before
Steam/MCC launch, run the read-only decision as the same privileged operator that owns the controls:

```bash
sudo python3 tools/interception/linux/tls_observer.py \
  --check-launch-window \
  --pid-file "$SCRATCH/observer.pid" \
  --ready-file "$SCRATCH/observer.ready"
```

The command emits only sanitized JSON: `observer_alive`, `listener_ready`, `run_identity_valid`,
`runtime_metadata_valid`, configured timeout, elapsed and remaining seconds, the minimum required
seconds, `safe_to_launch`, and sanitized failure reasons. It reads `/proc` and owned controls without
connecting to the listener. Missing, malformed, mismatched, replaced, expired, or inconsistent state
fails closed; false `safe_to_launch` exits nonzero. No key/certificate path, content, account datum,
or payload datum is emitted.

The direct baseline is also machine-recorded. A baseline document has format
`p0c2d1r1-direct-baseline-v1` and exactly records normal Steam launch, normal MCC launch,
`sign_in_mode` (`cached`, `interactive`, or `unknown`), Microsoft/Xbox identity success, main-menu
success, certificate/service-error presence, and clean shutdown. Check it with:

```bash
python3 tools/interception/linux/tls_observer.py --check-baseline "$SCRATCH/direct_baseline.json"
```

The rung cannot continue unless Steam and MCC launched normally, `identity_success == true`,
`main_menu_success == true`, `certificate_or_service_error == false`, and
`clean_shutdown == true`. Missing keys, wrong types, and vague operator prose fail closed; “baseline
looked okay” is not an accepted result.

Any separately authorized retry must use this exact order:

1. repository/environment gate;
2. direct baseline with explicit identity/menu assertions;
3. fully exit Steam/MCC;
4. create fresh scratch;
5. generate a fresh exact-host CA/leaf;
6. run final TLS-observer preflight;
7. install prefix-only CA trust;
8. start observer;
9. verify observer ready;
10. install exact-host redirect;
11. verify redirect and protected identity scope;
12. run the minimum-remaining-runtime gate;
13. only when `safe_to_launch == true`, start Steam/MCC immediately;
14. observe; and
15. roll back immediately once a sufficient result is obtained.

If step 12 fails, **do not launch Steam or MCC**. Roll back the redirect and prefix trust immediately
and record a pre-launch safety abort, never `D. OBSERVER NOT CONTACTED`. A new retry remains separately
authorized work; R1 does not create its scratch, certificate, trust, observer, redirect, or client
state.

## Retry 1 live result — P0-C2D1

`evidence/p0c2d1_tls_observation_retry1/` records the accepted retry
(`E-P0C2D1R1LIVE-001` through `E-P0C2D1R1LIVE-007`). The direct cached-identity baseline passed and
shut down cleanly. Fresh exact-host material passed the final preflight and was installed only into
the MCC Proton-Wine Root store. The observer published matching owned controls on
`127.0.0.77:443`; the redirect affected exactly one host and preserved all six protected identity
hosts.

The mandatory gate returned `observer_alive`, `listener_ready`, `run_identity_valid`,
`runtime_metadata_valid`, and `safe_to_launch` all true, with 188.894 seconds remaining against the
150-second minimum. Steam launch followed immediately. MCC made eight exact-SNI TLS 1.2 connections
using `ECDHE-RSA-AES256-GCM-SHA384`, negotiated no ALPN, and sent application data after every
handshake. This is `A. TLS CERTIFICATE ACCEPTED`.

The observer was deliberately not a server: it forwarded nothing and returned no application
response, so stats/store were unavailable during the redirected launch. Immediate exact rollback
restored hosts bytes/hash/size/inode, removed the listener and controls, verified the exact CA absent,
deleted all temporary certificate/key material, and was followed by a successful normal restoration
launch. The result supports proposing a separately authorized bounded application-layer passthrough
rung; it does not make the current reverse proxy ready.

## Phase boundary

P0-C2D0-R2 establishes only that the preflight, probe, and relay bounds now match the live rung's
authorized state and scope, under synthetic validation. It establishes no MCC request, response,
TLS acceptance or pinning verdict, settings manifest, endpoint authority, or production forwarding
behaviour, and it changes no architecture hypothesis.

**P0-C2D and the bounded P0-C2D1 certificate-acceptance question are complete. P0-C2E is not
started.** Retry 1 proves that the tested MCC/Proton path accepts the short-lived, prefix-trusted,
exact-host certificate sufficiently to send application data. It does not prove a working service,
safe upstream forwarding, response compatibility, or absence of every possible pinning mechanism.
Any passthrough rung remains separately authorized; `reverse_proxy.py` remains `NOT READY`. The
corrected tooling still awaits the separate Meta Muse Spark 1.2 read-only audit noted above.
