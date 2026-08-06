# Post-authentication interception

Whether one MCC title-service connection can be observed **after** identity has completed normally,
without disturbing sign-in. Every statement cites an evidence ID resolving to
`evidence/p0c2c_post_auth_interception/`.

**Current status: not yet achieved.** MCC signs in fine with no proxy, but a post-authentication
name-based redirect of the settings service does not intercept it, because MCC reuses a persistent
connection opened during boot.

## What was tried and what happened

| Step | Result | Evidence |
|---|---|---|
| Direct sign-in, no proxy, no redirect | Succeeds; main menu reached (cached session) | `E-P0C2C-001` |
| Redirect exactly `settings.svc.halowaypoint.com` → local observer, identity hosts untouched | Scope correct: one host redirected, identity unaffected | `E-P0C2C-002` |
| Trigger a settings refresh (title in/out) and observe | **MCC never contacts the observer** | `E-P0C2C-003` |
| Cause | **Connection reuse** — MCC holds a live TLS connection to the real settings IP, opened at boot before the redirect, and reuses it (never re-resolves) | `E-P0C2C-003` |
| CA acceptance / pinning | **Unresolved** — no handshake to the observer occurred | `E-P0C2C-004` |
| Rollback | Full, verified on disk and by end-to-end normal operation | `E-P0C2C-005` |

## Why the two obvious mechanisms both miss

- **Name-based `/etc/hosts` redirect (mechanism 1, used here).** Only consulted when MCC performs a
  fresh DNS lookup. MCC reused an existing connection, so it never looked up the name and never saw
  the override.
- **Exact-IP DNAT (mechanism 2, considered, not used).** Only affects *new* connections. A reused
  ESTABLISHED connection is not caught without forcing a reconnect, which is invasive and risks the
  session.

The deeper tension: cleanly observing (or trusting a CA for) the settings service wants the redirect
and CA in place **before** the connection is made — i.e. before boot — but boot is exactly where
identity happens, and identity is what must not be intercepted. P0-C2B showed the boot-time proxy
approach breaks sign-in; this rung shows the post-boot redirect approach misses the reused
connection. Between them they bound the problem.

## Certificate-trust caveat for any future attempt

Even if a connection is redirected, a second confound must be controlled: the temporary CA was
installed **after** MCC started (Stage ordering requires it), and a running process may not reload
its certificate store. A rejection would then be ambiguous between pinning and a stale store. Clean
certificate-trust evidence needs the CA present before the connection — which loops back to the
before-boot / identity tension above.

## What a future rung would need

1. A UI action **proven** to force a fresh settings fetch on a new connection (not a reused one), so
   a name redirect is actually consulted; or
2. exact-IP DNAT **plus** a deliberate, bounded reconnect of only the settings connection, accepting
   that this is more invasive; and, for trust evidence,
3. the CA present before the redirected connection is established, without running identity under
   interception.

Until one of those is worked out, no MCC title-service request has been observed and MCC's
certificate-trust behaviour for its own services remains unresolved (`E-P0C2A-005`, `E-P0C2C-004`).

## Safety properties held throughout

- Exactly one host redirected; every identity/Xbox-auth host rejected by the denylist and confirmed
  resolving normally.
- Temporary CA name-constrained to the single host, 2-day validity, refused for any excluded host.
- Observer recorded no bodies and no header values, returned a bounded `501`, never imitated the
  service.
- No key material, request/response body, capture, or proxy dump created or committed.
- All privileged commands run by the operator; no sudo password handled by the tooling.
