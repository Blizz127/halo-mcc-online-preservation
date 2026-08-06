# P0-C2B report: read-only MCC title-service request/response capture

**Outcome: no capture was taken.** MCC did not complete Microsoft/Xbox sign-in through the proxy,
so Stage B never became eligible and **nothing was decrypted at any point in this rung**.

Scope was the retail build banked in `evidence/p0b1_bazzite_proton_build_bank/` (appid `976730`,
buildid `19905945`). Halo Infinite is not used as evidence anywhere below.

## Starting gate

`main` was 1 commit ahead of `origin/main` because P0-C2A's instruction was "do not push". This was
raised rather than worked around; the operator authorized the push, and `main` == `origin/main` ==
`33d51f2` before Stage A began. Steam was running at gate time and was closed as part of Stage A
setup. All other gate conditions passed on first check, including the **P0-C2A rollback still being
intact**: all three temporary CAs absent from the Proton prefix, Launch Options empty, `/etc/hosts`
clean, no proxy or capture processes.

## Change made before retrying (so this was not a blind repeat)

P0-C2A's proxied sign-in had already failed once. Rather than re-run an identical test, the most
plausible mechanical cause was fixed first: the proxy's tunnel tore down **both** directions the
first time either side returned zero bytes. That breaks any exchange where one peer finishes sending
while still awaiting a reply — the exact shape of a multi-step authentication flow. The relay now
shuts down only the finished direction.

A `bytes_relayed` counter was added at the same time, so tunnel throughput became observable without
inspecting any content. That counter is what makes Claim 2 below possible.

## Claim 1 — MCC does not complete Xbox Live sign-in through an explicit proxy, even with zero decryption

**Claim:** With the proxy in tunnel mode and every identity host blind-tunnelled, MCC again failed
to sign in: the operator observed an Xbox Live sign-in error and the main menu was never reached.
Seven `CONNECT` requests were made, to `login.live.com`, `login.microsoftonline.com`,
`sisu.xboxlive.com`, `title.mgt.xboxlive.com`, `api.epicgames.dev` (×2), and
`modules-cdn.eac-prod.on.epicgames.com`. **All 7 were `blind_tunnel_excluded`. Zero were
terminated. Zero `tls_result` values were recorded.**

This reproduces `E-P0C2A-004` under a materially different proxy implementation.

**Evidence IDs:** `E-P0C2B-001` (`proxy_route_summary.json`)

**Reproduction:** Start `metadata_proxy.py --mode tunnel`; set MCC Launch Options to
`http_proxy=http://127.0.0.1:8080 https_proxy=http://127.0.0.1:8080 %command%`; launch MCC.

**Counter-evidence / limits:** **The cause remains unresolved and is deliberately left so.**
Diagnosing it would require decrypting exactly the identity traffic this rung forbids. The failure
is reproducible across two rungs and two proxy implementations, which makes an incidental bug in a
single implementation unlikely — but "unlikely" is not "excluded", and no stronger claim is made.

**Confidence:** High that the failure occurred and that nothing was decrypted. None as to cause.

## Claim 2 — The tunnels were functioning; the failure was not a relay failure

**Claim:** All five distinct hosts carried substantial bidirectional traffic through the tunnel:
`api.epicgames.dev` 62,852 bytes, `title.mgt.xboxlive.com` 28,358, `sisu.xboxlive.com` 20,768,
`login.live.com` 11,528, `modules-cdn.eac-prod.on.epicgames.com` 6,209. The tunnels were not
closing early, starving the exchange, or failing to relay.

**Evidence IDs:** `E-P0C2B-002` (`proxy_route_summary.json` → `stage_a.hosts[*].bytes_relayed`;
`tls_metadata.md`)

**Counter-evidence / limits:** Byte volume shows bytes moved, **not** that they moved correctly.
Latency, ordering, connection reuse, HTTP/2 or HTTP/3 negotiation differences, and IP-level
behaviour (a proxied connection presents a different source path to the server) are all unexamined.
This narrows the cause away from gross relay failure; it does not identify it.

This is why the half-close fix matters as evidence: the mechanical hypothesis most likely to explain
P0-C2A's failure was fixed, and the failure persisted anyway.

**Confidence:** High for the byte counts. Deliberately weak for what they imply.

## Claim 3 — Stage B did not run, and no MCC data was decrypted, captured, or stored

**Claim:** Because Stage A did not reach the main menu, Stage B was not eligible under this rung's
own rule. In consequence:

- the decrypt allowlist was **never activated** (the proxy ran in tunnel mode throughout),
- **no temporary CA was generated or installed** in the Proton prefix,
- **no host was TLS-terminated** — 0 of 7 connections,
- **no request or response body was read, buffered, or written**,
- no raw proxy dump, HAR, SAZ, or pcap was created.

**Evidence IDs:** `E-P0C2B-003` (`proxy_route_summary.json`, `tls_metadata.md`,
`rollback_verification.txt` §10)

**Confidence:** High — asserted by three independent records and by the absence of any capture
artifact in the repository, which a test enforces
(`test_no_captured_body_artifacts_are_tracked_in_the_repository`).

## Claim 4 — Rollback restored normal operation, operator-confirmed

**Claim:** After rollback, MCC launched, **Microsoft/Xbox sign-in succeeded**, and the main menu
loaded normally. The proxied sign-in failure did **not** persist.

Rollback was performed in the order P0-C2A's mistake taught — MCC stopped and Launch Options cleared
**before** the proxy was stopped — so the client was never left pointing at a dead port. That
mistake did not recur.

**Evidence IDs:** `E-P0C2B-004` (`rollback_verification.txt`, all items PASS)

**Counter-evidence / limits:** Items 7–8 are operator observation of the client UI, not an
instrumented measurement. Items 1–6 and 9–10 were machine-checked against on-disk state.

**Confidence:** High — two independent routes agree.

## Host selection (recorded, though never used)

Had Stage B run, the single allowlisted host would have been **`settings.svc.halowaypoint.com`**:

- **MCC contacts it.** Confirmed in P0-C1 (`E-P0C1-001`), owned by the MCC game process with 71
  socket samples.
- **Lowest risk of the confirmed inventory.** Named for read-only settings/configuration. It is not
  identity, XSTS, MPSD, entitlements, bans, stats, notifications, telemetry, matchmaking, purchases,
  or TURN/QoS — every one of which is excluded.
- **Read-only by expectation**, so a captured exchange would carry no write semantics and no
  progression or inventory effect.
- **Relevant to H-002** (whether MCC exposes a machine-readable settings/authority manifest), which
  is the open question a settings endpoint would most directly inform.
- Runner-up `gamecms-hacs.svc.halowaypoint.com` was rejected: a content-management service is more
  likely to return copyrighted narrative or asset material, which complicates committing even a
  schema.

The allowlist was defined but **never activated**. `request_shape.json` and `response_schema.json`
record `captured: false` rather than speculative content.

## Synthetic fixture — tooling demonstration only

`synthetic_fixture.json` is generated from **invented input defined in this rung**, not from any
captured traffic, and carries a warning to that effect in its first field. It exists to prove the
schema/fixture tooling is deterministic and value-free ahead of a rung that can actually use it. It
is not MCC evidence and must never be cited as such.

## Privacy handling

- Exclusion is **structural**: an excluded host is never TLS-terminated, so there is no decrypted
  byte to leak. The check runs before any mode branch and the denylist **wins over the allowlist**
  (tested).
- The decrypt allowlist is **exact-match, default-deny**, and **fails closed** when empty. Suffix
  and prefix spoofs (`settings.svc.halowaypoint.com.attacker.invalid`,
  `evil.settings.svc.halowaypoint.com`) are rejected (tested).
- No header **values**, query **values**, or bodies are accepted by any code path — only names,
  types, and lengths.
- `schema_extract.extract_schema` retains no scalar from its input by construction, and flags
  identifier-shaped **key names** as `unresolved` so a later rung must justify them.

## Hypothesis impact

`docs/ARCHITECTURE_HYPOTHESES.md` **H-007** ("Proxy-based TLS capture is sufficient") is materially
**narrowed, not resolved**: proxy-based capture is now shown insufficient for MCC's *sign-in phase*,
because MCC fails to authenticate through an explicit proxy even when nothing is decrypted. It is
**not** rejected — whether a session that signs in *without* a proxy survives one being enabled
afterwards is untested, and that is the obvious next experiment. No other hypothesis changes.

## Interpretation boundary

Established: that proxied sign-in does **not** complete, reproducibly, across two proxy
implementations; that the tunnels relayed substantial traffic; that no decryption occurred.

**Not** established: the cause of the sign-in failure; whether one MCC title-service host can be
decrypted; the shape of any MCC request or response; whether MCC accepts a temporary CA; whether an
unmodified upstream response remains usable. Also not established, and unchanged: authentication
bypass, token minting, endpoint coverage, server-replacement compatibility, write-endpoint
behaviour, matchmaking architecture, native Windows behaviour, or a universal MCC certificate-trust
policy.

## Next gate

**P0-C2C — MCC Endpoint Manifest and Configuration-Surface Discovery**, requiring its own explicit
authorization. Given this rung's result, P0-C2C should not assume proxy-based access: the open
question is now *why* MCC will not authenticate through a proxy, and whether any observation path
exists that does not disturb sign-in.
