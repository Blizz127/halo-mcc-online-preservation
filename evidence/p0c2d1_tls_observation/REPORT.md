# P0-C2D1 report: exact-host TLS observation lifecycle failure

**Outcome: `E. SNI / OBSERVER CONTRACT FAILURE`.** The exact-host redirect and observer scope were
correct, but the 240-second observer reached `total_deadline` before the authorized Steam launch
command was issued. Its fixed-schema log contains zero observations. This is an orchestration and
lifecycle failure, not evidence that MCC declined to contact the observer, rejected the temporary
certificate, or uses certificate pinning.

Exact `/etc/hosts` rollback, prefix trust removal, certificate-material deletion, and a separate
normal post-rollback launch all succeeded. P0-C2D1 therefore remains incomplete, with certificate
acceptance, SNI, TLS version, cipher, ALPN, application data, and pinning unresolved.

## Starting state and baseline — E-P0C2D1-001

The run started from `main` at `70fce68d7c30011ffee21f86a26cd2dae1b2fc0a`, equal to
`origin/main`, zero ahead and zero behind, with a clean worktree and no nonignored untracked files.
Read-only gates found no proxy environment, project interception/capture process, listener, redirect,
or Steam/MCC/Proton-Wine process. The selected host and all six protected identity hosts resolved
normally.

The direct baseline launched MCC through Steam and the operator reported no certificate/service
error, but did not explicitly confirm identity or main-menu success. That makes the baseline evidence
incomplete; the run should not use it to claim baseline identity or menu success. See
`direct_baseline.json`.

## Certificate and prefix-only trust — E-P0C2D1-002 / E-P0C2D1-003

A two-day test CA and exact-host leaf were generated in mode-`0700` repository-external scratch,
with all files mode `0600`. The leaf SAN and CA name constraint both contained only
`settings.svc.halowaypoint.com`; the leaf key matched its certificate. Certificate fingerprints and
validity metadata are retained, but no PEM/DER body or private key is recorded.

The exact CA thumbprint was installed only into MCC's Proton-Wine Root store and verified present.
The host OS trust store was never modified. After rollback, exact-thumbprint deletion succeeded,
the post-delete Wine query and an independent read-only `system.reg` parse both reported absent, and
all CA/leaf/key files were deleted. See `certificate_metadata.json` and `trust_install.json`.

## Correct redirect scope, insufficient remaining window — E-P0C2D1-004

The bounded observer started at `15:58:38-05:00` on exactly `127.0.0.77:443`, with a 240-second
runtime and eight-connection cap. Its PID and ready controls appeared only after the listener was
active. `host_redirect.py` recorded exact prior `/etc/hosts` bytes, hash, size, and inode before the
operator installed one guarded line:

```text
127.0.0.77 settings.svc.halowaypoint.com # P0C2D-REDIRECT (temporary; exact rollback required)
```

Scope verification found exactly one line and sentinel, selected-host IPv4 equal to `127.0.0.77`,
no selected-host IPv6 bypass, all six identity hosts global and nonlocal, and inode `4621125`
preserved. However, the operator confirmed installation only at `16:02:24`, scope verification began
at `16:02:36`, and the observer deadline was `16:02:38`. There was no safe launch window left. The
launch should have been refused and rollback begun immediately. See `redirect_verification.json`.

## Observer result and classification — E-P0C2D1-005

The observer's sanitized final document is:

```json
{
  "elapsed_seconds": 240.103,
  "exit_reason": "total_deadline",
  "format": "p0c2d1r0-tls-observer-v2",
  "observation_count": 0,
  "observations": [],
  "total_timeout_seconds": 240.0
}
```

The Steam launch command was issued at `16:02:43`, after the observer deadline. The redirect was
therefore briefly left pointing at a dead listener, and rollback became mandatory. `D. OBSERVER NOT
CONTACTED` is invalid here because MCC did not receive the promised bounded observation window.
Classification E is based on the failed observer lifecycle/runbook contract, not on SNI—none was
observed. No TLS version, cipher, ALPN, application data, certificate verdict, protocol result, or
pinning verdict exists. See `tls_observation.json`.

## Rollback and restored operation — E-P0C2D1-006

The operator ran the exact hash- and inode-guarded rollback. Verification restored the original 604
bytes, SHA-256 `58ab06ea4280182a38c8176bc4eda7d83815cc08aec9e9ed082a71a47eebf28b`,
inode `4621125`, and mode `0644`; the project line and sentinel were absent. Resolver-cache flush and
fresh lookups restored normal selected-host and protected-host resolution. Observer PID/ready
controls disappeared, its process ended, and `127.0.0.77:443` closed.

After exact prefix trust removal and certificate-material deletion, a separate normal Steam/MCC
launch completed identity and reached the main menu with no certificate/service error. MCC quit
normally; Steam's normal shutdown request completed; final process inspection found no MCC,
Proton-Wine game, Steam, interception, or capture process. See `rollback_verification.txt`.

## Validation

The targeted P0-C2D0/P0-C2D1 suite passed `132` tests and the full suite passed `251` tests.
`compileall`, `git diff --check`, JSON parsing, text-only evidence inspection, and the sensitive-
material scan passed. No CA, certificate body, private key, raw TLS, request/response, header value,
token, cookie, account identifier, private path, capture, or scratch control is committed.

## Coordination deviations, retained rather than hidden

The first manual redirect command was split by terminal paste wrapping and failed before mutation;
immediate inspection proved `/etc/hosts` unchanged. A private mode-`0700` scratch script then carried
the exact generated guarded command without changing its checks. More importantly, setup latency
consumed almost the entire observer window, yet the launch proceeded. This violated the runbook's
dead-observer control and is the reason for classification E.

## Interpretation and next gate

This run changes no architecture hypothesis. P0-C2D's opaque-transport result still stands, but
P0-C2D1 has not observed MCC TLS behavior. Certificate acceptance and pinning remain unresolved.
P0-C2E remains unstarted, and reverse-proxy/application-layer passthrough remains unauthorized and
`NOT READY`.

A later retry requires separate authorization and a corrected operator sequence that starts the
observer only after all non-observer prerequisites and guarded redirect/rollback commands are ready,
then refuses redirect or launch unless enough of the bounded window remains. No application-layer
passthrough rung is justified by this result.
