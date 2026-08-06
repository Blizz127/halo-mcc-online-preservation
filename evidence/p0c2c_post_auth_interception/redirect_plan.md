# P0-C2C redirect plan

## Selected host

`settings.svc.halowaypoint.com` — and only this host.

- P0-C1 attributed it to the MCC game process (`E-P0C1-001`, 71 socket samples).
- It is a settings/configuration service, not identity, XSTS, MPSD, entitlements, progression,
  matchmaking, telemetry, TURN, QoS, purchases, or enforcement.
- It is the lowest-risk known candidate for investigating H-002.

No other host was added at any point.

## Mechanism chosen: exact-host `/etc/hosts` override

`/etc/nsswitch.conf` resolves `hosts:` via `files` **before** `dns`, so a single `/etc/hosts`
line overrides resolution for exactly one literal name and nothing else. This is the narrowest
name-based redirect available:

- it cannot express a wildcard or a domain suffix (a hosts entry is one literal name);
- the target is validated to equal the one selected host verbatim, and rejected if it is a
  sibling, parent, suffix, wildcard, or any host on the exclusion denylist;
- the entry points the name at `127.0.0.77`, a dedicated loopback address used by nothing else,
  so "traffic to that address is the observer" needs no further argument;
- it is installed by appending (`tee -a`) to preserve the `/etc/hosts` inode, which matters
  because pressure-vessel bind-mounts the host `/etc/hosts` into the Proton container — a replace
  (new inode) would not propagate to the running MCC, an append does.

## Why not the network-redirect fallback (mechanism 2)

An exact-destination DNAT was considered as the documented fallback for when DNS caching defeats
mechanism 1. It was **not** used, because the failure here was **connection reuse**, not DNS
caching: MCC held a live, persistent TLS connection to the real settings service established during
boot, before any redirect. DNAT only affects *new* connections, so it would not have caught the
reused one without forcing a reconnect — and forcing a reconnect (killing the socket) is invasive,
risks disturbing the authenticated session, and is out of this rung's bounded scope.

## Rollback

- Redirect: `grep -v <sentinel> /etc/hosts > tmp && sudo cp tmp /etc/hosts` (inode-preserving),
  then `resolvectl flush-caches`.
- Temporary CA: `wine_trust.py remove --thumbprint <sha1>`, verified absent both by live
  `reg query` and, after MCC quit, in the on-disk `system.reg`.
- Observer: stopped; `127.0.0.77:443` confirmed closed.

All privileged commands were run by the operator; no sudo password was handled by the tooling.
