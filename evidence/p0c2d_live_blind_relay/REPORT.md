# P0-C2D report: live single-host blind-relay validation

**Outcome: `A. BLIND RELAY PASS`.** With a pre-launch exact-host redirect in place, MCC completed
cached Microsoft/Xbox identity, contacted `settings.svc.halowaypoint.com` through an opaque local
TCP relay, exchanged encrypted bytes in both directions, and reached the main menu without a
certificate or service error. Exact rollback completed before the relay deadline, and a separate
normal launch after rollback succeeded.

This is retail observation under `docs/EVIDENCE_POLICY.md` class 2. It proves transport behavior
only. TLS was never terminated, no payload was inspected, and this rung establishes no request,
response, manifest, certificate-pinning, or service-authority claim.

## Starting state and direct baseline — E-P0C2D-001

The run started from `main` at
`92024f2551be6b2c11a6a836231c450ccfb4ae0e`, equal to `origin/main`, zero ahead and zero behind,
with a clean worktree and no nonignored untracked files. The corrected `blind-relay` preflight
passed with Steam/MCC closed, no proxy environment, no interception/capture process, no listener on
`127.0.0.77:443`, normal selected-host resolution, six safe identity-host resolutions, repository-
external paths, and no CA/Wine arguments.

Before any relay or redirect, MCC launched normally through Steam. Cached Microsoft/Xbox identity
succeeded, the main menu loaded, no certificate/service error appeared, and MCC and Steam shut down
cleanly. See `direct_baseline.json`.

## Fresh upstream TLS verification — E-P0C2D-002

A fresh lookup selected literal IPv4 `172.212.71.217`. `upstream_probe.py` connected to that
literal address with SNI and hostname verification for `settings.svc.halowaypoint.com`, required
normal certificate validation, offered `h2` and `http/1.1`, negotiated TLS 1.3 and `h2`, and sent
zero application bytes and no HTTP request. Only certificate metadata and its SHA-256 leaf
fingerprint were retained; no DER or PEM was written. See `upstream_validation.json`.

## Exact redirect scope — E-P0C2D-003

The relay listened only on `127.0.0.77:443` with bounds `240/240/8` and production lingering.
PID and ready controls carried the same PID and run ID. The metadata log initially contained zero
connections and only its fixed payload-free schema.

`host_redirect.py` recorded the exact prior `/etc/hosts` bytes, SHA-256, size, and inode, then
emitted the guarded append for exactly one line:

```text
127.0.0.77 settings.svc.halowaypoint.com # P0C2D-REDIRECT (temporary; exact rollback required)
```

Verification found exactly one line and sentinel, selected-host IPv4 equal to `127.0.0.77`, no
selected-host IPv6 bypass, and all six protected identity hosts still resolving to global nonlocal
addresses. The `/etc/hosts` inode remained `4621125`. See `redirect_verification.json`.

## Live blind-relay result — E-P0C2D-004

MCC completed cached identity and reached the main menu with no visible certificate or service
error. The selected service made one relay connection:

| Opened | Duration | Client to upstream | Upstream to client | Error |
|---|---:|---:|---:|---|
| `2026-08-06T14:29:27.306580000-05:00` | 17.131 s | 4,728 bytes | 29,226 bytes | none |

The exact Steam launch timestamp was not instrumented; it is recorded as unknown rather than
fabricated. Launch was authorized only after scope verification at `14:28:12`, and the selected-
service connection supplies the first direct machine timestamp. The relay later recorded
`exit_reason: total_deadline`. This is not a rollback failure: `/etc/hosts` was restored at
`14:30:01`, fifteen seconds before the `14:30:16` deadline.

The byte counts prove opaque bidirectional transport, not payload meaning or correctness. The relay
did not terminate TLS, modify bytes, persist peer addresses, or record payload-derived fields. See
`relay_result.json`.

## Rollback and restored operation — E-P0C2D-005

Rollback restored exact prior `/etc/hosts` bytes, SHA-256, size, and inode; removed the only
authorized line and sentinel; flushed the accepted resolver cache; and restored normal selected and
identity-host resolution. Relay PID/ready controls disappeared, the process and workers ended, and
`127.0.0.77:443` closed.

A separate post-rollback launch then completed cached identity, reached the main menu with no
certificate/service error, and shut down cleanly. See `rollback_verification.txt`.

## Coordination deviations, retained rather than hidden

Several operator/Codex coordination attempts ended before a live launch: Steam remained open at
two preflights; one relay command wrapped mid-argument; one used an unset shell variable; and two
readiness-only relay windows were stopped or allowed to expire. One earlier redirect was installed
but rolled back before launch when insufficient time remained. Every such attempt stopped before
MCC ran under redirection, and exact rollback plus restored normal operation were proven before the
successful run. They carry no A-F classification and are not MCC evidence.

## Interpretation and next gate

Established: a pre-launch exact-host blind relay can carry the settings service while normal cached
identity and main-menu bootstrap succeed; the boot-time connection is therefore interceptable by
this opaque transport without redirecting identity hosts.

Not established: plaintext API/schema, settings authority, CA acceptance, certificate pinning,
authentication replacement, or service compatibility. P0-C2E remains unstarted.

This result supports considering a separately authorized, exact-host TLS/SNI/ALPN observation rung,
because contact and normal bootstrap are now proven. It does not itself authorize that rung or CA
use.
