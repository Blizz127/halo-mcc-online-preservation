# P0-C2A report: Bazzite HTTPS visibility and trust-path validation

Scope: determine how HTTPS proxying and certificate trust behave through Bazzite → Steam → Proton →
Wine → MCC, for the retail build banked in `evidence/p0b1_bazzite_proton_build_bank/`
(appid `976730`, buildid `19905945`).

**No Microsoft identity, Xbox authentication, XSTS, MPSD, entitlement, purchase, or
account-management traffic was captured, redirected, decrypted, logged, or modified.** No sign-out
occurred, the cached identity was not deleted, the Proton prefix was not cleared, and no fresh
Microsoft login was forced. Halo Infinite is not used as evidence anywhere below.

## Starting-gate deviation (recorded, not hidden)

The gate required P0-C1 commit `45288d6` to be pushed. It was **not** pushed at the start of this
rung, because the preceding rung's instruction was explicitly "Do not push". This was raised rather
than worked around, and the operator authorized the push before P0-C2A began. `main` and
`origin/main` were both at `45288d6` before Stage A started.

MCC was also still running at gate time and was terminated at the operator's instruction.

## Tooling decision: mitmproxy was not installed

The rung's instruction was to prefer a tool such as mitmproxy **only if** it can be configured to
redact sensitive headers and bodies. mitmproxy was not present, and installing it on this immutable
OS would have meant rpm-ostree layering plus a reboot, or a large pip dependency tree.

A purpose-built proxy and observer were written instead, because redaction becomes **structural
rather than configured**:

- Bodies are never parsed or buffered by any code path, so no configuration mistake can cause one
  to be logged.
- Header **values** are never accepted by any function; only names are.
- Excluded hosts are never TLS-terminated in the first place, so there is no decrypted byte to leak.

That last property is what actually protected identity traffic in Stage C, where every single MCC
connection turned out to be to an excluded host.

## Claim 1 — A native Linux client can use an explicit HTTPS proxy

**Claim:** A native Bazzite Linux client reached the local HTTPS test service through an explicit
proxy and completed the request (TLS 1.3, HTTP 200). The proxy recorded the destination and the TLS
SNI (`p0c2a.test`) **without terminating TLS**.

**Evidence IDs:** `E-P0C2A-001` (`tls_observations.md` §Stage A, rows A2/A3;
`proxy_test_matrix.json` → `objective_1_…`)

**Reproduction:** Start `tools/interception/linux/tls_observer.py` and
`tools/interception/linux/metadata_proxy.py --mode tunnel`, then run
`tools/interception/test_client/linux_client.py --proxy-host 127.0.0.1 --proxy-port 8080 --ca <ca.crt>`.

**Counter-evidence / limits:** This is a loopback test against a synthetic service. It shows the
proxy path and SNI visibility work; it says nothing about any real endpoint.

**Confidence:** High, for exactly that narrow claim.

## Claim 2 — A Windows client under Proton can use an explicit proxy, but only via environment variables

**Claim:** A WinHTTP client running inside the MCC Proton prefix used the explicit proxy when
`http_proxy`/`https_proxy` were set, and did **not** when the proxy was configured through
`WinHttpRequest.SetProxy` (COM) or the WinINET `HKCU` registry values. Each mechanism was aimed at a
distinct RFC 5737 documentation address so the results could not be conflated.

**Evidence IDs:** `E-P0C2A-002` (`proxy_test_matrix.json` →
`objective_2_…mechanisms_tested`; `tls_observations.md` §Explicit-proxy mechanisms)

**Counter-evidence / limits:** Two earlier rounds of this test produced *wrong* answers and are
recorded because the failure modes are instructive:

1. A loopback target made every mechanism look ignored — WinHTTP bypasses the proxy for loopback,
   and Wine did not honour the `<-loopback>` override token.
2. A subsequent round reported "no CONNECT" for all three mechanisms because the proxy had failed to
   start with `EADDRINUSE` while a previous instance still held the port. Nothing was listening.
   The conclusion was discarded and the test re-run against a confirmed-live proxy.

This tests **one** WinHTTP client. It does not establish behaviour for WinINET-based code paths, and
MCC loads both `winhttp.dll` and `wininet.dll` (P0-C1 module list).

**Confidence:** High for the three mechanisms as tested; not generalisable to other Windows HTTP
stacks in the prefix.

## Claim 3 — The Proton prefix has its own Root store, writable without administrative privilege

**Claim:** The MCC prefix carries an independent certificate store at
`HKLM\Software\Microsoft\SystemCertificates\Root\Certificates\<SHA1>`, holding **167** entries
written when the prefix was created. Installing a CA there made the Proton WinHTTP client accept a
certificate it had previously rejected, and required **no administrative privilege**. The host
system store (`/etc/pki/ca-trust/source/anchors`, admin-only) was never modified.

**Evidence IDs:** `E-P0C2A-003` (`trust_store_matrix.md`)

**Counter-evidence / limits — the IP-address trap:** Installing the CA appeared at first *not* to
work: the WinHTTP client still failed with `0x80072f7d`. The variable was not trust but the URL
form — Wine's WinHTTP rejected a certificate presented for a **bare IP address** even with a
matching IP SAN. With a hostname URL and the same trust state, the request succeeded. A rung that
tested only with an IP would have concluded, confidently and wrongly, that Proton ignores the prefix
trust store.

Whether Wine enforces `NameConstraints` was **not** isolated and remains unresolved: constrained and
unconstrained CAs behaved identically, but both were confounded by the IP issue.

**Confidence:** High that the prefix store exists, is independent, is honoured, and needs no admin
rights. Unresolved for name-constraint enforcement.

## Claim 4 — MCC honours an explicit proxy, and its earliest traffic is authentication

**Claim:** Launched from Steam with `http_proxy`/`https_proxy` set via Launch Options, MCC routed
traffic through the proxy: **7 CONNECT requests** were observed, to `login.live.com`,
`login.microsoftonline.com`, `sisu.xboxlive.com`, `title.mgt.xboxlive.com`, `api.epicgames.dev`
(×2), and `modules-cdn.eac-prod.on.epicgames.com`. **All 7 were on the hard-exclusion list and all 7
were blind-tunnelled; zero were decrypted.**

While proxied, MCC reported *"Error encountered while signing into Xbox Live"*.

**Evidence IDs:** `E-P0C2A-004` (`proxy_test_matrix.json` → `objective_4_…`;
`tls_observations.md` §Stage C)

**Counter-evidence / limits:** The sign-in failure was **not diagnosed**, because diagnosing it
would have required inspecting the identity traffic this rung forbids. The honest statement is
narrow: routing MCC through an explicit proxy is detectable in MCC's behaviour, and the first thing
MCC does on the network is authenticate. Whether the failure was caused by the proxy's tunnelling
behaviour, a timeout, or MCC objecting to a proxy at all is **unknown**.

**Confidence:** High that MCC honours the environment-variable proxy and that these hosts were
contacted. None for the cause of the sign-in failure.

## Claim 5 — MCC certificate acceptance and pinning are UNRESOLVED

**Claim:** This rung **cannot** say whether MCC accepts a locally trusted CA, rejects it, or pins
certificates.

**Evidence IDs:** `E-P0C2A-005` (`tls_observations.md` §Certificate acceptance by MCC)

**Reasoning:** Every MCC connection observed was to an excluded host and was blind-tunnelled by
design, so no MCC connection was ever TLS-terminated with the test CA. There was no opportunity to
observe acceptance, rejection, or a pinning alert. This is a direct consequence of the exclusions
working as intended — the only way to have answered it here would have been to terminate identity
traffic, which is exactly what the rung prohibits.

MCC never reached a non-identity title service in this session, because sign-in failed first.

**Confidence:** N/A — recorded as unresolved rather than guessed.

## Claim 6 — Rollback restored normal MCC operation, confirmed by end-to-end operator observation

**Claim:** After the rung's changes were reverted, MCC returned to fully normal operation. With
Steam fully closed and reopened and the Launch Options field empty, the operator observed:

- MCC launched normally;
- **Microsoft/Xbox sign-in succeeded** — the failure seen under the proxy in Claim 4 did not persist;
- the main menu loaded with **no proxy, certificate, or service error**;
- the Halo: Reach menu was reachable;
- MCC exited normally.

This closes the loop on Claim 4's observed side effect: the sign-in failure was a **transient
condition of the proxied configuration**, not a persistent change to the client, the prefix, or the
account state.

**Evidence IDs:** `E-P0C2A-006` (operator observation, recorded in `rollback_verification.txt` §7;
machine-checked items in the same file §§1–6)

**Reproduction steps:**
1. Quit MCC and fully close Steam.
2. Clear the Launch Options field for appid `976730`.
3. Reopen Steam, launch MCC, sign in, reach the main menu and the Halo: Reach menu, then exit.

**Counter-evidence / limits:** This is an **operator observation of the client UI**, not an
instrumented measurement — no capture was running, by design, since the point was to confirm
untouched normal operation rather than to observe it. It establishes that the reverted state works;
it does not re-verify the machine-checkable items, which were verified separately and directly
against on-disk state (prefix registry, process table, listening ports, `/etc/hosts`, host trust
store) in `rollback_verification.txt` §§1–6. Steam needed a **full restart** for the cleared Launch
Options to take effect, which is worth knowing for any future rung that sets them.

**Confidence:** High. Every reverted item was independently confirmed by two routes — direct
on-disk inspection and end-to-end client behaviour — and the two agree.

## Stage D — not required, not performed

Stage D was explicitly conditional on Stage C establishing that explicit proxying does **not** reach
MCC. It does reach MCC (Claim 4), so Stage D was not run:

- no hostname was selected for redirection,
- `/etc/hosts` was never modified,
- no DNS override was created,
- no traffic was redirected to a local TLS observer.

Verified in `rollback_verification.txt` §5.

## Privacy handling

- **Hard exclusions enforced structurally.** `tools/interception/linux/exclusions.py` is the single
  source of truth; the check runs before any termination branch, and matching is on registrable
  suffix so `login.live.com.attacker.invalid` cannot masquerade as `login.live.com`. Unknown or
  empty hosts **fail closed** (treated as excluded). Anything under `auth.xboxlive.com` is excluded
  by a parent guard, so a newly-appearing auth host is excluded by default.
- **No bodies, ever.** No code path parses or buffers a request or response body.
- **No header values, ever.** Only header names are accepted, lowercased and sorted.
- **Token-shaped redaction** exists as a backstop only (JWT, `XBL3.0 x=…`, long hex, SteamID64- and
  XUID-shaped digits) — it is not the primary control.
- **No key material committed.** The CA and leaf private keys were written mode `0600` into an
  ignored scratch directory outside the repository and are recorded here only by fingerprint.
- The raw proxy and observer logs stay in local scratch and are not committed.

## Rollback

All changes were reverted and independently verified against on-disk state rather than trusting the
tools' own exit codes — see `rollback_verification.txt`:

| Change | Reverted | Verified |
|---|---|---|
| 3 test CAs in the prefix Root store | Yes | Absent from `system.reg` |
| WinINET `ProxyEnable` (`0x0` → `1` → `0x0`) | Yes | Restored |
| WinINET `ProxyServer` (absent → set → absent) | Yes | Absent |
| Proxy and observer processes | Stopped | None running; ports 8080/8443 free |
| Host system trust store | Never modified | No `p0c2a` anchors present |
| `/etc/hosts` / DNS | Never modified | No redirect entries |
| Steam Launch Options | Cleared by operator | Confirmed by operator after a full Steam restart (`E-P0C2A-006`) |
| **End-to-end normal operation** | **n/a — restored state** | **Operator-observed: launch, sign-in, main menu, Reach menu, clean exit (`E-P0C2A-006`)** |

Rollback is therefore confirmed by two independent routes that agree: direct inspection of on-disk
state (§§1–6 of `rollback_verification.txt`) and end-to-end client behaviour (Claim 6). The Xbox Live
sign-in failure observed under the proxy did **not** persist after rollback, which establishes it as
a transient condition of the proxied configuration rather than a change to the client, the prefix,
or the account.

**One operational mistake is recorded here rather than omitted:** the proxy was stopped while MCC
was still running with `http_proxy` pointing at it, which left MCC hanging on a dead port until the
operator quit it and cleared Launch Options. Correct order is: stop MCC, clear Launch Options, then
stop the proxy. A second, milder lesson from the same sequence: **Steam must be fully restarted**
before a cleared Launch Options field takes effect.

## Interpretation boundary

Established: explicit-proxy use and non-use per client and mechanism; the certificate stores that
govern Bazzite, Proton/Wine, and MCC; that Wine trust needs no admin privilege; and that MCC
honours an environment-variable proxy.

**Not** established, and not to be inferred: authentication bypass, token forgery, server
compatibility, endpoint schemas, replacement-service correctness, native Windows behaviour, whether
MCC pins certificates, or general behaviour for all MCC endpoints. **One host or client behaving a
given way does not prove every MCC service uses the same HTTP or TLS stack.** No hypothesis in
`docs/ARCHITECTURE_HYPOTHESES.md` is promoted by this rung.

## Next gate

The next authorized rung is **P0-C2B — Read-Only MCC Title-Service Request/Response Capture**, which
requires its own explicit authorization. P0-C2A authorizes no interception of identity traffic, no
CA installation beyond a bounded test, no DNS redirection, and no service implementation.
