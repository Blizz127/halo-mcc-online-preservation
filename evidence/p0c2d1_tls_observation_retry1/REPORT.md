# P0-C2D1 retry 1: exact-host TLS certificate accepted

**Outcome: `A. TLS CERTIFICATE ACCEPTED`.** With only
`settings.svc.halowaypoint.com` redirected to the bounded metadata-only TLS observer, MCC made eight
connections with exact SNI. Every connection completed TLS 1.2 using
`ECDHE-RSA-AES256-GCM-SHA384`, negotiated no ALPN, and sent application data after the handshake.
This directly proves that the tested MCC/Proton path accepted the fresh, prefix-trusted, short-lived
exact-host certificate. It does not prove absence of every possible pinning mechanism outside this
path.

The observer was not a Halo server emulator. It did not forward decrypted traffic upstream and did
not provide an application response. Stats/store being unavailable during the redirected launch was
therefore expected. Normal service operation returned after complete rollback.

## Starting gate and direct baseline — E-P0C2D1R1LIVE-001

The retry started on `main` at `ff1dbd20a267b1e291c942485294a4b6d6708d9e`, equal to
`origin/main`, zero ahead and zero behind, with a clean tree and no nonignored untracked files. No
Steam, MCC, project interception, listener, proxy environment, redirect, sentinel, or previous
P0-C2D1 CA remained. The selected host and all six protected identity hosts resolved globally and
away from `127.0.0.77`.

The normal direct baseline used cached Microsoft/Xbox identity, reached the main menu without a
certificate/service error, and shut down cleanly. The accepted machine decision returned
`contract_valid: true` and `safe_to_continue: true`. See `direct_baseline.json`.

## Fresh exact-host material and final preflight — E-P0C2D1R1LIVE-002

`local_ca.py` generated new material in a mode-`0700`, repository-external, non-symlink scratch
directory. All four files were mode `0600`. The leaf SAN contained only
`settings.svc.halowaypoint.com`; the critical CA name constraint permitted only that exact host and
excluded its subdomains. CA and leaf validity were two days, and the leaf key matched the
certificate. Only sanitized metadata and fingerprints are retained in `certificate_metadata.json`.

The final `p0c2d_preflight.py --stage tls-observer` decision passed every check: synchronized Git
state, closed Steam/MCC, no proxy/listener/project process/redirect, normal selected and protected
host resolution, safe external outputs, executable Proton Wine, exact SAN and key mode, and fresh
thumbprint absence. No trust was installed until that decision passed.

## Prefix-only trust and observer readiness — E-P0C2D1R1LIVE-003

The fresh CA was installed only into the MCC Proton-Wine Root store. The registry add returned zero,
the exact post-install query returned present, and an independent read-only `system.reg` parse also
reported present. The host OS trust store was not touched. See `trust_install.json`.

The first privileged observer command used a relative script path; PolicyKit changed the privileged
working directory, so Python exited before binding or creating controls. No redirect existed. The
successful invocation used the same accepted tool by absolute path and published matching root-owned
PID/ready controls for one run identity only after listening on exactly `127.0.0.77:443`. The HTTP
reverse proxy remained absent and `NOT READY`.

## Exact redirect and launch-window gate — E-P0C2D1R1LIVE-004 / 005

The hash- and inode-guarded append installed exactly one selected-host line and one project sentinel.
Scope verification found selected IPv4 equal only to `127.0.0.77`, no selected-host IPv6 bypass, all
six protected identity hosts unaffected, observer readiness intact, and `/etc/hosts` inode `4621125`
preserved. A validated exact rollback payload was prepared before the launch gate. See
`redirect_verification.json`.

Immediately before launch, the accepted gate reported:

```json
{
  "observer_alive": true,
  "listener_ready": true,
  "run_identity_valid": true,
  "runtime_metadata_valid": true,
  "configured_timeout_seconds": 240.0,
  "elapsed_seconds": 51.106,
  "remaining_seconds": 188.894,
  "minimum_required_seconds": 150.0,
  "safe_to_launch": true,
  "failure_reasons": []
}
```

Steam launch was issued immediately at `17:20:33-05:00`, with no intervening check. See
`launch_window_gate.json`.

## TLS observation — E-P0C2D1R1LIVE-006

The first connection arrived about 54 seconds after Steam launch. The observer reached its configured
eight-connection cap in 121.663 seconds. All eight sanitized observations agreed:

- exact SNI: `settings.svc.halowaypoint.com`;
- TLS handshake completed;
- TLS version: `TLSv1.2`;
- cipher: `ECDHE-RSA-AES256-GCM-SHA384`;
- ALPN: none negotiated;
- post-handshake application data: yes;
- certificate verdict: `accepted_certificate`;
- protocol result: `http1_metadata`.

This satisfies classification A. No body, header value, token, cookie, account datum, peer address,
raw TLS, request payload, or response was retained. The committed `tls_observation.json` further
removes method, path, query-name, and header-name metadata because the retry requested only the
listed TLS/application-presence fields.

Identity and main-menu success during the redirected launch were not explicitly recorded before
immediate rollback and are reported as such. The operator later noted stats/store were unavailable;
that is consistent with the observer deliberately returning no application response and is not a
certificate-rejection result.

## Immediate rollback and restoration — E-P0C2D1R1LIVE-007

As soon as sufficient evidence was available, MCC/Steam received a normal shutdown request. The
exact rollback restored the original 604 bytes, SHA-256
`58ab06ea4280182a38c8176bc4eda7d83815cc08aec9e9ed082a71a47eebf28b`, inode `4621125`,
and mode `0644`; the selected-host line and sentinel were absent. Resolver state was flushed and the
selected plus all protected hosts again resolved normally.

The observer ended at the eight-connection cap with `exit_reason: connection_cap_reached`; its
listener and PID/ready controls disappeared. Exact-thumbprint deletion returned zero, the Wine query
and independent registry parse both reported absent, and the temporary CA, leaf, and private keys
were deleted. No project interception process remained.

A separate normal post-rollback launch completed Microsoft/Xbox identity, reached the main menu,
showed no certificate/service error, and shut down cleanly. Final checks found no project CA,
redirect, listener, control, or interception process. An unrelated non-MCC UMU/Wine workload appeared
after preflight; it was neither touched nor recorded with a private path and did not change the exact
MCC-prefix or selected-host evidence.

## Interpretation and next boundary

This retry narrows H-007: exact-host, pre-launch TLS termination is sufficient for MCC to trust the
prefix-installed CA and send HTTP/1.x application data. The result supports proposing a separately
authorized, bounded application-layer passthrough rung, because certificate acceptance is no longer
the blocker on this tested path. It does **not** authorize the current reverse proxy: safe upstream
forwarding, response framing, persistence, upgrades, trailers, informational responses, half-close,
and rollback behavior remain unproven, and `reverse_proxy.py` remains `NOT READY`.

P0-C2E was not started.

## Validation

- `python3 -m pytest -q tests/test_p0c2d0_prelaunch.py`: `149 passed`;
- `python3 -m pytest -q`: `268 passed`;
- `python3 -m compileall -q tools tests`: passed with no output;
- tracked and new-file `git diff --check`: passed;
- all six JSON evidence files parsed and the committed baseline returned `safe_to_continue: true`;
- sensitive-material scan found no certificate/key body, private-key marker, credential value,
  account identifier, raw traffic, private path, live scratch path, or excluded request metadata;
- no added file has a certificate, key, capture, archive, or binary-material suffix.
