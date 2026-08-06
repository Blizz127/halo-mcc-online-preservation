# P0-C2D1-R0 report: TLS observer live-bounds correction

**Outcome: the authorized P0-C2D1 exact-host TLS/SNI/ALPN observation rung was halted at its
starting gate, before the direct baseline and before any live action, on an operator decision after
two structural tooling gaps were found by reading the tools' source. No live classification (A–F) is
possible and none is claimed. No system, network, Steam, MCC, Wine, certificate-store, or
`/etc/hosts` state was changed; no certificate or key was generated; no production service was
contacted. This rung corrects the gaps the halt exposed; it banks no MCC observation.**

The pattern is the one P0-C2D0-R2 recorded: tooling that satisfies its synthetic contract but cannot
gate — or in this case cannot survive — the live rung it was written for. R2 reconciled the relay's
bounds with measured launch behaviour. The observer was never given the same treatment, and this
rung supplies it.

## E-P0C2D1R0-001 — what the halted attempt established, and what it did not

The repository gate passed on first check: branch `main`, `HEAD` and `origin/main` both
`bc0c25a202c25ff203a32b9d3aa17d117baf0a3a`, zero ahead, zero behind, clean tracked tree, no
nonignored untracked files, `git diff --check` clean.

Read-only host inspection before the halt found the environment in the expected pre-rung state: no
proxy environment variables, `/etc/hosts` free of any project sentinel or manual selected-host entry
(inode `4621125`, 604 bytes, mode `0644`), nothing listening on `127.0.0.77:443`, no Steam, MCC,
relay, observer, proxy, or capture process running, and the MCC Proton prefix Root store holding 156
entries with no project CA — the P0-C2C thumbprint `64548D5A11AB5B9DECE2CB5D4215AA577F6FC104`
verified absent by read-only `system.reg` parse, without starting Wine.

**Not established by the halted attempt:** any MCC behaviour, TLS handshake, SNI value, ALPN result,
certificate verdict, pinning verdict, sign-in result, menu result, request shape, response schema,
settings authority, or endpoint manifest. The experiment did not run. Reporting a `D. OBSERVER NOT
CONTACTED` or an `F. BASELINE FAILURE` would be false: the observer was never started and the direct
baseline was never attempted.

## E-P0C2D1R0-002 — the observer's runtime bound could not cover the measured live timeline

`tls_observer.py` carried `MAX_SECONDS = 120.0`, enforced on the production path — `run_observer`
raises when `total_timeout` exceeds it — with a CLI default of `30.0` seconds and a default
`--max-connections` of `1`. Those are synthetic-era values. They were never reconciled with the live
launch timeline, and two accepted measurements show 120 s is not enough:

| Measurement | Value | Source |
|---|---:|---|
| MCC launch to title-service resolution | 72 s | `E-P0C1-003` |
| Redirect scope verification to the settings connection arriving at the local listener | 75 s | `E-P0C2D-004` (`14:28:12` → `14:29:27`) |

The second figure is the binding one, and it is a *lower* bound on what the observer must survive.
The authorized rung starts the observer (step 8) **before** installing the redirect (step 9), so the
observer's clock additionally has to absorb the `/etc/hosts` install and the full scope verification
that precede the 75 s interval. The usable margin inside 120 s was roughly 20–35 s, entirely
consumed by any Steam cold-start delay.

The consequence is not merely a wasted run. An expired observer produces a result that reads as
`D. OBSERVER NOT CONTACTED` — a claim about MCC — when the true cause is the observer having exited
first. It also leaves the installed redirect pointing at a dead listener, so MCC's settings host
receives a refused connection until rollback.

**Why the accepted tooling did not catch this.** The same reason R2 recorded. The committed suite
tested the observer's synthetic contract — SNI exactness, `h2` non-parsing, header-name redaction,
application-data-required acceptance, stalled-handshake bounding, control-file lifecycle — and every
one of those tests is real. None of them asserted anything about how long a live run has to last,
and the relay's live-bounds consistency test (`test_relay_recommended_live_bounds_are_internally_
consistent`) had no observer counterpart. A suite that never states a bound cannot detect that the
bound is wrong.

## E-P0C2D1R0-003 — the rung's preflight step cannot execute in its stated order

A second gap, found in the same source read and recorded rather than worked around silently.

The authorized rung runs the corrected preflight at step 4 and generates the exact-host certificate
at step 6. `p0c2d_preflight.py --stage tls-observer` **requires** `--cert` and `--key`
(`run_preflight`: `missing` is non-empty, so `checks["stage"]["pass"]` is `False`), and its Wine
CA-absence check is all-or-none on `--prefix`, `--proton-wine`, and `--ca-thumbprint` — the
thumbprint being of a CA that does not exist until step 6. The `tls-observer` preflight therefore
cannot pass before the certificate is generated.

This is a step-ordering defect in the rung instruction, not a tool defect: the stage-aware
certificate contract is exactly what R2 built (`E-P0C2D0R2-003`) and is correct. The resolution for
a future live run is to generate the certificate into private scratch first — that writes only
repository-external, mode-`0600` material and changes no system state — and then run the preflight
with all five arguments supplied. It is recorded here so the next live attempt does not rediscover
it at its gate.

No certificate was generated during this rung. The halt came first.

## E-P0C2D1R0-004 — corrected observer bounds and a recorded exit reason

`tls_observer.py` now carries the same class of live-bounds block the relay received in R2, with the
measurements named rather than the numbers guessed.

| Constant | Value | Why |
|---|---:|---|
| `MAX_SECONDS` | `prelaunch_relay.MAX_SECONDS` (300.0) | One hard runtime bound across the live interception tools. Raised from 120.0 to the relay's already-accepted maximum rather than to a new number invented here; a longer experiment still needs a new rung |
| `OBSERVED_LAUNCH_TO_TITLE_SERVICE_SECONDS` | 72.0 | Measured in P0-C1 (`E-P0C1-003`) |
| `OBSERVED_REDIRECT_VERIFY_TO_CONNECT_SECONDS` | 75.0 | Measured in P0-C2D (`E-P0C2D-004`) |
| `RECOMMENDED_LIVE_SECONDS` | 240.0 | Redirect install + scope verify + Steam start + launch-to-title-service, with margin, inside the 300 s maximum. Equal to the relay's recommendation, because the window is the same window |
| `RECOMMENDED_LIVE_MAX_CONNECTIONS` | 8 | Reconnect headroom, and the reason is sharper for the observer than for the relay — see below |

CLI defaults now use the recommendations (`--seconds 240`, `--max-connections 8`) instead of `30.0`
and `1`. `MAX_CONNECTIONS` is unchanged at 8.

**Why the connection default matters here specifically.** The observer has no lingering mode: it
stops accepting once `len(observations)` reaches the cap. With the old default of 1, the observer
exited after the first connection while the redirect was still installed — so MCC's *retry* would
have met a refused connection. That retry is not incidental traffic; whether MCC retries after a
handshake is part of how a rejected certificate is distinguished from an accepted one, which is the
question this rung exists to answer. A cap of 8 keeps the observer present for it.

Lingering was deliberately **not** added to the observer. Unlike the relay, which must outlive its
connection because it is carrying a live session, the observer's purpose is complete once it has its
observations, and a bounded cap plus a recorded exit reason covers the hazard without adding an
untested code path. The runbook control is the same as the relay's and is complementary, not an
alternative: roll the redirect back **before** observer expiry.

**Exit reason.** The observer previously recorded no reason for ending, so a run that expired before
the client arrived was indistinguishable in its log from a run that stayed up and proved the client
never came — precisely the misreading `E-P0C2D1R0-002` describes. Every run now records
`exit_reason` (`total_deadline` or `connection_cap_reached`), `observation_count`,
`total_timeout_seconds`, and `elapsed_seconds`, and the log format moves to
`p0c2d1r0-tls-observer-v2`. All four fields are run metadata; no payload byte, header value, query
value, or peer address is added, and a test asserts that directly.

## Privacy and mutation boundary

No key, certificate, capture, payload byte, token, account identifier, or private path is committed.
Synthetic tests use temporary directories, loopback, high unprivileged ports, and reserved
`.invalid`/`.test` names. No test invoked `sudo`, started Steam, MCC, or Wine, modified `/etc/hosts`,
DNS, routing, firewall, proxy, or a certificate store, ran a packet capture, or contacted a
production service. Host inspection during the halted attempt was read-only throughout: file reads,
`/proc` and socket-table inspection, and a `system.reg` text parse that does not start Wine.

## Phase boundary

P0-C2D1-R0 establishes only that the observer's runtime bounds and exit accounting now match the
live rung's measured timeline, under synthetic validation. It establishes nothing about MCC.

**P0-C2D remains complete. P0-C2D1 is halted before its baseline and remains not completed. P0-C2E
remains not started.** The reverse proxy remains `NOT READY` with no runnable network path. No
architecture hypothesis is promoted, narrowed, or otherwise changed by this rung;
`docs/ARCHITECTURE_HYPOTHESES.md` is untouched because no MCC evidence was gathered.

The corrected observer supports re-running the authorized P0-C2D1 live rung with adequate margin,
with the step reordering in `E-P0C2D1R0-003` applied. It does not itself authorize that run, any CA
generation, any Wine trust installation, or any redirect.
