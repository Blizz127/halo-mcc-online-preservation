# Title-service capture

Status of efforts to observe MCC's own title-service HTTP exchanges. Every statement cites an
evidence ID resolving to `evidence/p0c2b_title_service_capture/`.

**Current status: no MCC title-service exchange has been captured.** In every tested explicit-proxy
configuration, Xbox sign-in failed rather than completing, and every rung so far has stopped there
rather than decrypt authentication traffic.

## What is blocking capture

| Observation | Evidence |
|---|---|
| MCC honours `http_proxy`/`https_proxy` and routes traffic through the proxy | `E-P0C2A-004` |
| With traffic proxied, Xbox Live sign-in failed in both tested proxy configurations (does not prove all methods fail) | `E-P0C2A-004`, `E-P0C2B-001` |
| The failure is not a relay failure: tunnels carried 6–63 KB per host bidirectionally | `E-P0C2B-002` |
| Fixing the most plausible mechanical cause (tunnel half-close teardown) did **not** fix it | `E-P0C2B-002` |
| The failure does not persist: after rollback, sign-in succeeds normally | `E-P0C2B-004` |
| Cause: **unresolved**, deliberately — diagnosing it means decrypting identity traffic, which is forbidden | `E-P0C2B-001` |

Because MCC never reaches the main menu while proxied, it never issues a title-service request
through the proxy, so there is nothing to capture even before the question of decryption arises.

## Selected host, if capture becomes possible

**`settings.svc.halowaypoint.com`** — defined but never activated in the decrypt allowlist.

- MCC contacts it, owned by the game process, 71 socket samples (`E-P0C1-001`).
- Lowest-risk member of the confirmed inventory: read-only settings/configuration, and not identity,
  XSTS, MPSD, entitlements, bans, stats, notifications, telemetry, matchmaking, purchases, or
  TURN/QoS.
- Most directly informs **H-002** (does MCC expose a machine-readable settings/authority manifest).
- `gamecms-hacs.svc.halowaypoint.com` was the runner-up and was rejected: a content service is more
  likely to return copyrighted material, complicating even a schema.

## Capture controls (built, tested, unused on real data)

The machinery exists and is proven by tests; it has simply never had real traffic to act on.

- **Default deny.** Every host is blind-tunnelled unless it appears verbatim in the decrypt
  allowlist. An empty allowlist decrypts nothing.
- **Denylist beats allowlist.** An excluded identity host cannot be decrypted even if someone adds
  it to the allowlist.
- **Exact-match only.** `settings.svc.halowaypoint.com.attacker.invalid` and
  `evil.settings.svc.halowaypoint.com` are both rejected.
- **Redaction before disk.** No header value, query value, or body is accepted by any code path —
  only names, types, and lengths.
- **Schema retains no values.** `schema_extract` describes shape only, and marks identifier-shaped
  key names `unresolved` so a later rung must justify them.
- **Synthetic fixtures are deterministic** and generated from the schema alone, so a committed
  fixture can carry no production data.

## What a future rung would need to resolve first

The blocking question is no longer "can we decrypt?" but **"why won't MCC authenticate through a
proxy?"** — and it must be answered without decrypting authentication traffic. Untested avenues, in
rough order of how much they disturb the client:

1. **Sign in first, proxy second.** Establish a session with no proxy, then enable the proxy for
   post-authentication traffic only. This directly tests the narrowed form of H-007 and is the
   cheapest next experiment.
2. **Selective proxying.** Route only non-identity hosts through the proxy and let identity traffic
   go direct, so authentication never traverses it.
3. **Protocol-level differences.** A proxied path forces HTTP/1.1 `CONNECT` semantics and changes the
   source path presented upstream; whether MCC's auth is sensitive to that is unexamined.

## Interpretation boundary

Established: that proxied sign-in failed in both tested configurations; that tunnels relay correctly; that nothing has
been decrypted.

**Not** established: the cause of the failure; any MCC request or response shape; whether MCC accepts
a locally trusted CA; whether MCC pins certificates. `E-P0C2A-005` recorded certificate acceptance as
unresolved and **it remains unresolved after this rung**, for the same structural reason — MCC never
gets far enough for the question to arise.
