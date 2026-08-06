# P0-C2D0-R2 report: live-preflight contract correction

**Outcome: the first attempted P0-C2D live rung halted at its starting gate, before the direct
baseline. No live classification (A–F) is possible and none is claimed. No system, network, Steam,
MCC, Wine, certificate-store, or `/etc/hosts` state was changed, and no production service was
contacted. This rung corrects the tooling gaps the attempt exposed; it banks no MCC observation.**

The P0-C2D0 tooling passed its synthetic contract and the Codex Sol adversarial audit's re-check,
yet could not gate the live rung it was built for. That gap is the subject of this report.

## E-P0C2D0R2-001 — what the halted live attempt established

The attempt ran the repository gate and the accepted read-only preflight, then stopped. Four
findings, three structural and one operator precondition:

| # | Finding | Kind | Where |
|---|---|---|---|
| 1 | The preflight required the repository to be exactly **one commit ahead** of `origin/main`. The authorized live state is **0 ahead / 0 behind**, so the gate could never pass. | Structural tooling gap | `p0c2d_preflight.py` `_run_git_checks`, comparing the raw `rev-list` string to `"0\t1"` |
| 2 | The preflight **unconditionally required a certificate and private key**, though the authorized blind-relay rung forbids generating or installing a CA. `--cert`/`--key` were mandatory and `_certificate_check` ran on every path. | Structural tooling gap | `p0c2d_preflight.py` `run_preflight` |
| 3 | **Steam was running.** | Operator precondition, not a code defect | live host |
| 4 | **No accepted upstream TLS probe existed.** The only client-side TLS tool, `tools/interception/test_client/linux_client.py`, sends `GET /p0c2a-test` after the handshake and records none of the required fields. | Structural tooling gap (missing tool) | step 5 of the live rung had no tool |

Findings 1, 2, and 4 are contract mismatches between the tooling and the live rung it was written
to gate. **The accepted P0-C2D0 audit did not catch any of them.** That audit was adversarial
against the tools' *synthetic* contract — stale controls, bind failure, rollback exactness, redaction
— and every finding it raised was real. It did not test the tools against the live rung's authorized
state and scope, and the committed test suite pinned the same wrong expectations the code held
(`"0\t1"` asserted in two tests; the certificate gate satisfied by constructing a CA in the fixture).
A suite that encodes an assumption cannot detect it. The separate Meta Muse Spark 1.2 read-only
audit **remains pending** and is not claimed as passed.

**Not established by the halted attempt:** any MCC behaviour, sign-in result, menu result, TLS
verdict, certificate acceptance, pinning verdict, request shape, response schema, settings authority,
or endpoint manifest. The experiment did not run. Reporting it as a baseline failure would be false —
the direct baseline was never attempted.

## E-P0C2D0R2-002 — Git-state expectations are now explicit

Ahead and behind are computed separately from
`git rev-list --left-right --count <remote-ref>...HEAD` (left = behind, right = ahead) and compared
against `--expected-ahead` / `--expected-behind`, which default to `0`/`0`. The result reports both
the expected and the actual values. `--expected-branch`, `--expected-head`, and
`--expected-remote-tip` were already configurable and remain so; `--expected-parent` became optional
and is checked only when supplied; `--remote-ref` replaced the hardcoded `origin/main` string.

Fail-closed behaviour: any `rev-list` output that is not exactly two non-negative integers is
`ahead_behind_malformed` with both actuals `null`; a non-zero Git exit or a raised `OSError` /
`SubprocessError` records the failing query. No commit hash appears anywhere in the tool — a test
asserts the source contains no 40-hex literal and no `"0\t1"` comparison.

Both live states are now expressible without editing code: the pushed synchronized state (`0/0`) and
a local-only review state (`--expected-ahead 1`).

## E-P0C2D0R2-003 — certificate checks are stage-aware and never inferred

`--stage` is required and takes `blind-relay` or `tls-observer`. It is never inferred from which
arguments happen to be present.

Under `blind-relay`: `--cert`, `--key`, `--prefix`, `--proton-wine`, and `--ca-thumbprint` are all
optional *and supplying any of them is a failure* — their presence means the operator is running the
wrong contract, which is reported rather than ignored. No certificate file is opened and no Wine
prefix or registry is inspected; both checks report `not_applicable_blind_relay`. Tests prove the
non-invocation directly, by substituting a `_certificate_check` and a `wine_presence` dependency that
raise if called, and by asserting the scratch directory is byte-identical before and after.

Under `tls-observer`: `--cert` and `--key` are required and the certificate check runs as before; the
Wine CA-absence check stays all-or-none on `--prefix`, `--proton-wine`, `--ca-thumbprint`.

## E-P0C2D0R2-004 — upstream TLS probe added

`tools/interception/linux/upstream_probe.py` validates one literal candidate address for the selected
hostname before any redirect exists. It dials a literal IPv4 address only and performs no DNS;
verification is `CERT_REQUIRED` with `check_hostname=True` and SNI
`settings.svc.halowaypoint.com`; it advertises ALPN `h2, http/1.1`; and it **sends no application
byte at all** — no HTTP request, no probe payload — then closes. The synthetic test proves this from
the server side: the server completes the handshake and reads end-of-stream rather than a request.

Recorded: selected hostname, candidate IP, TLS version, cipher name/protocol/bits, negotiated ALPN,
certificate subject, issuer, validity window, SHA-256 leaf fingerprint, verification result, and an
error class plus a bounded detail string on failure. Not recorded: any certificate body, DER, or PEM.
A test asserts no PEM body fragment appears in the output.

Production rejection is explicit rather than inherited: hostname-where-an-IP-is-expected, IPv6,
loopback, private, link-local, multicast, reserved, unspecified, broadcast, RFC 5737
documentation ranges, RFC 2544 benchmarking, RFC 5771 MCAST-TEST-NET, and RFC 6598 shared address
space. The hostname is a module constant with no CLI flag, so no normal invocation can retarget it.
Tests drive `synthetic_probe`, which independently refuses anything that is not loopback, refuses
low ports, refuses the production hostname, and requires an explicit CA file.

**No test contacts a production service.** Every production-path assertion is a rejection that raises
before a socket is created.

## E-P0C2D0R2-005 — relay live bounds and the dead-relay hazard

The hard maximum is **unchanged** at 300 s. Recommended live bounds are now named constants and
tested for internal consistency:

| Constant | Value | Why |
|---|---|---|
| `OBSERVED_LAUNCH_TO_TITLE_SERVICE_SECONDS` | 72.0 | Measured in P0-C1 (`E-P0C1-003`) |
| `RECOMMENDED_LIVE_SECONDS` | 240.0 | Steam start + 72 s + operator latency, with margin, inside the 300 s cap |
| `RECOMMENDED_LIVE_IDLE_SECONDS` | 240.0 | Equal to total: a healthy settings connection is expected to sit quiet, and tearing it down mid-session would corrupt the observation. The total deadline stays the single bound |
| `RECOMMENDED_LIVE_MAX_CONNECTIONS` | 8 | Reconnect headroom, so open/close/reopen does not exhaust the cap under a live redirect |

The previous defaults (120 s total, 30 s idle, 4 connections) would have ended the run, or torn down
a quiet connection, well inside the window the redirect was installed for.

**Dead-relay hazard.** `serve()` previously returned as soon as the connection cap was reached,
which with a low cap could leave an installed redirect pointing at an exited listener. A code change
was implemented rather than deferring to the runbook: `linger_until_deadline` (used by the production
CLI path) keeps the run alive to its deadline after the cap is reached; over-cap connections are
closed immediately and recorded as `ConnectionCapReached` rather than silently refused. Every run now
records an `exit_reason` — `total_deadline`, `connection_cap_reached`, or
`connection_cap_reached_lingering` — in the metadata log, so a cap-bounded run can never be read as a
complete one. The log format moved to `p0c2d0r2-safe-relay-v2`. The runbook additionally requires
rollback before relay expiry; the two controls are complementary, not alternatives.

**Additional finding, not from the live attempt.** While writing the probe's address classifier, the
relay's own production contract was found to accept **IPv4 multicast**: it tested only
`is_global`, and CPython reports `224.0.0.1` as global. `validate_production_contract` now
disqualifies unspecified, loopback, link-local, multicast, reserved, and private addresses
explicitly before the global check. This was never reachable in practice — the live rung supplies an
address validated by the probe — but it was a real hole in a safety contract and is recorded rather
than quietly patched.

## Privacy and mutation boundary

No key, certificate, capture, payload byte, token, account identifier, or private path is committed.
Synthetic tests use temporary directories, loopback, high unprivileged ports, and reserved
`.invalid`/`.test` names. No test invoked `sudo`, started Steam, MCC, or Wine, modified `/etc/hosts`,
DNS, routing, firewall, proxy, or a certificate store, ran a packet capture, or contacted a
production service. The scratch directory created during the halted live attempt held no payload and
is recorded only as `<LOCAL_SCRATCH>/p0c2d-live`.

## Phase boundary

P0-C2D0-R2 establishes only that the preflight, probe, and relay bounds now match the live rung's
authorized state and scope, under synthetic validation. It establishes nothing about MCC.

**P0-C2D remains not started. P0-C2E remains not started.** No architecture hypothesis is promoted,
narrowed, or otherwise changed by this rung; `docs/ARCHITECTURE_HYPOTHESES.md` is untouched because
no MCC evidence was gathered. The corrected tooling is ready for a bounded independent read-only
audit, which should treat the live rung's authorized state and scope — not only the synthetic
contract — as part of what it checks.
