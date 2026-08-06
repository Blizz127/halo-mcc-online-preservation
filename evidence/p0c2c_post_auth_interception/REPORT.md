# P0-C2C report: post-authentication single-host title-service interception

**Outcome: MCC signed in normally without a proxy, but the post-authentication single-host redirect
did not result in an observer contact — because MCC reuses a persistent connection to the settings
service established during boot.** Nothing was decrypted; certificate acceptance and pinning remain
unresolved.

Scope was the retail build banked in `evidence/p0b1_bazzite_proton_build_bank/` (appid `976730`,
buildid `19905945`). Halo Infinite is not used as evidence. The single selected host was
`settings.svc.halowaypoint.com` and no other host was added.

## Starting gate

`main` was 1 commit ahead of `origin/main` because P0-C2B's instruction was "do not push"; the
operator authorized the push, and `main` == `origin/main` == `8ce3631` before this rung began. All
other gate conditions passed on first check, including the P0-C2A/B rollback still being intact
(no temporary CA in the prefix, `/etc/hosts` clean, Launch Options empty, no proxy/observer
processes).

## Claim 1 — MCC signs in normally with no proxy and no redirect active

**Claim:** With no proxy environment and no redirect installed, MCC reached the main menu and
Microsoft/Xbox identity was established through the normal direct network path. Sign-in used a
cached session (no credential prompt), which is consistent with prior rungs and still satisfies the
baseline: **identity was established without interception.**

**Evidence IDs:** `E-P0C2C-001` (`baseline.json`)

**Counter-evidence / limits:** Because sign-in was cached, this rung did not exercise a fresh
credential entry. That is immaterial to the objective — the point is that identity completed on the
direct path, off the redirect — but it means "sign-in works directly" is shown for the cached-session
case, which is the case that matters here (it is the case P0-C2B could not get past while proxied).

**Confidence:** High.

## Claim 2 — Exactly one host was redirected; identity hosts were never affected

**Claim:** After the menu was reached, `settings.svc.halowaypoint.com` was redirected to the local
observer at `127.0.0.77` via a single `/etc/hosts` line, and **only** that host. Throughout the
redirect window, `login.live.com`, `xsts.auth.xboxlive.com`, and `user.auth.xboxlive.com` continued
to resolve to their real Microsoft/Xbox addresses (`redirected_to_observer: false` for each). The
observer bound the dedicated loopback address `127.0.0.77:443`, used by nothing else.

**Evidence IDs:** `E-P0C2C-002` (`redirect_plan.md`, scope verification in `baseline.json`)

**Reproduction:** `host_redirect.py verify settings.svc.halowaypoint.com` after the operator installs
the one-line redirect. The tool resolves the selected host and a set of identity hosts and asserts
only the selected one points at the observer.

**Counter-evidence / limits:** Scope was verified by resolution, which reflects what a fresh lookup
returns. It does not, by itself, prove MCC performed a fresh lookup — that is the subject of Claim 3.

**Confidence:** High that the redirect affected exactly one host and no identity host.

## Claim 3 — MCC did not contact the observer, due to connection reuse

**Claim:** MCC never connected to the redirected observer. Zero observations were recorded. During
the trigger (navigating into Halo: Reach and back to the title-select surface) and a 25-second
observation window, MCC held a **live, persistent TLS connection to the real settings service**
(`20.184.175.6:443`, same `20.184.0.0/16` as the resolved settings dispatcher), owned by the game
process (`MAIN_THREAD`, pid 472944, with `wineserver`). No new connection to the settings range
appeared. Because MCC reused the connection established at boot — before the redirect — it never
re-resolved the hostname, so the `/etc/hosts` override was never consulted.

**Evidence IDs:** `E-P0C2C-003` (`tls_observation.json`, `reused_connection` evidence)

**Reproduction:** With the redirect active and the observer listening, poll `ss` for connections to
the settings `/16` and for observer contact while triggering menu navigation.

**Counter-evidence / limits:** This shows reuse for **this** session and **this** trigger. It does
not prove MCC never re-resolves settings under any circumstance — a longer session, a cache/keepalive
expiry, or a different UI action might force a new connection. What is established is that the
menu-navigation trigger, over the observed window, did not, and that a persistent connection was
demonstrably held. The exact-destination DNAT fallback (mechanism 2) was considered and **not** used:
it affects only new connections, so it would not catch a reused one without forcing a reconnect,
which is invasive and out of scope.

**Confidence:** High that no contact occurred and that a reused connection was held. Medium for
"reuse is the sole cause" — a lack of any retriggerable settings request over this window is an
alternative that this rung cannot fully separate from reuse.

## Claim 4 — Certificate acceptance and pinning remain UNRESOLVED

**Claim:** Whether MCC would accept the temporary CA for this host, reject it, or pin the certificate
is **unresolved**, for the third rung running. No TLS handshake to the observer occurred, so there
was no opportunity to observe any verdict.

**Evidence IDs:** `E-P0C2C-004` (`tls_observation.json` → `pinning: unresolved`,
`tls_handshake_attempts: 0`)

**Counter-evidence / limits:** A secondary confound is worth recording for a future rung: the CA was
installed **after** MCC had started (the rung's Stage ordering requires it), so even had a handshake
occurred, a rejection could not have been cleanly attributed to pinning versus the running process
not having reloaded its certificate store. Resolving certificate trust cleanly needs the CA present
**before** the connection is made — which, for the settings service, means before boot, and boot is
where identity happens. That tension is the core difficulty these C2 rungs keep hitting.

**Confidence:** N/A — recorded as unresolved rather than guessed.

## Claim 5 — Full rollback restored normal operation, operator-confirmed

**Claim:** All changes were reverted and verified against on-disk state: the `/etc/hosts` redirect
removed (0 sentinel lines; `/etc/hosts` byte-identical to the pre-run backup minus our line), normal
DNS restored (`settings.svc.halowaypoint.com` → `20.184.144.194`), the temporary CA removed from the
prefix and verified absent both by live `reg query` and — after MCC quit flushed the registry — in
the on-disk `system.reg`, the observer stopped and `127.0.0.77:443` closed, the host trust store
never touched, and Launch Options empty throughout. The operator then restarted Steam, launched MCC,
and confirmed sign-in and the main menu work normally.

**Evidence IDs:** `E-P0C2C-005` (`rollback_verification.txt`)

**Counter-evidence / limits:** One item read as a false failure at first: immediately after removal,
the on-disk `system.reg` still showed the CA because Wine flushes the prefix registry lazily while
MCC runs. The live `reg query` already showed it gone; quitting MCC flushed the file and the on-disk
check then passed too. This is recorded rather than smoothed over.

**Confidence:** High — two independent routes (on-disk inspection and end-to-end behaviour) agree.

## Privacy handling

- The redirect target is validated to be exactly the one selected host; siblings, parents, suffixes,
  wildcards, and any denylisted identity host are rejected (tested). Identity hosts can never be
  minted a certificate or redirected.
- The temporary CA is **name-constrained to exactly `settings.svc.halowaypoint.com`** (critical
  extension), 2-day validity, `pathlen:0`, so even a forgotten copy can vouch for that one host and
  nothing else.
- The observer records only handshake metadata and never a body or a header value; it returns a
  bounded `501` and never imitates the real service.
- CA and leaf private keys were written mode `0600` into ignored scratch outside the repository and
  are recorded here only by fingerprint. No key, body, or capture artifact is committed.
- All privileged commands (observer on port 443, `/etc/hosts` edit) were run by the operator. The
  tooling never requested, received, stored, or passed a sudo password.

## Hypothesis impact

`docs/ARCHITECTURE_HYPOTHESES.md` **H-007** is further narrowed. P0-C2B showed proxy capture is
insufficient for the *sign-in phase* (MCC will not authenticate through a proxy). This rung shows the
complementary obstacle for the *post-authentication* phase: a name-based single-host redirect applied
after boot does not intercept the settings service, because MCC holds and reuses a persistent
connection opened before the redirect. Together they map the difficulty precisely — neither a
boot-time proxy (breaks sign-in) nor a post-boot name redirect (misses reused connections) yields a
decrypted title-service exchange. H-007 stays **Unproven/narrowed**, not rejected: a redirect
installed while the settings connection is genuinely re-established (e.g. via a UI action that forces
a fresh fetch, or exact-IP DNAT combined with a deliberate reconnect) is untested.

## Interpretation boundary

Established: direct sign-in succeeds before redirection; an exact-host post-auth redirect affects
exactly one host and no identity host; MCC did not contact the observer over this window; a reused
persistent settings connection was held; full rollback works.

**Not** established, and not to be inferred: authentication bypass, token minting, endpoint coverage,
replacement-service compatibility, native Windows behaviour, universal MCC TLS behaviour, whether MCC
pins certificates, or that the settings service is authoritative for any configuration. No MCC
request or response was observed.

## Next gate

**P0-C2D — MCC Endpoint Manifest and Configuration-Surface Discovery**, requiring its own explicit
authorization. Given this rung, P0-C2D should not assume a redirect will intercept a reused
connection: it needs either a trigger proven to force a fresh settings fetch, or a mechanism that
acts before the connection is established without running identity under interception.
