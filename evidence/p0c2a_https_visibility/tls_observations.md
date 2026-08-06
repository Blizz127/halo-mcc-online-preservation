# P0-C2A TLS observations

Connection-level observations from the local test service, the explicit proxy, and MCC itself.
No TLS session against any real host was terminated or decrypted at any point in this rung.

## How acceptance was determined (and why the obvious signal is wrong)

Under **TLS 1.3 the server completes its side of the handshake before the client has validated the
certificate.** A server therefore records a "successful" handshake even when the client is about to
reject it. Reading `tls_completed` as acceptance would have inverted several results below.

The reliable signal is whether the client went on to **send a request**:

| Server-side observation | Actual client verdict |
|---|---|
| handshake fails, TLS alert received | rejected during handshake (e.g. `unknown_ca`) |
| handshake completes, **no request** follows | **rejected after handshake** |
| handshake completes, request arrives | accepted |

The observer records this explicitly as `client_verdict`, so the distinction survives into the
evidence rather than living in someone's head.

## Stage A — local synthetic service (`p0c2a.test` / `localhost`, loopback only)

| # | Client | Trust | Transport | Result |
|---|---|---|---|---|
| A1 | Linux (OpenSSL) | none | direct | Rejected. `unable to get local issuer certificate`; server saw alert **`TLSV1_ALERT_UNKNOWN_CA`** |
| A2 | Linux | CA supplied | direct | **Accepted.** TLS 1.3, HTTP 200, 134-byte synthetic body |
| A3 | Linux | CA supplied | **via explicit proxy** | **Accepted.** HTTP 200. Proxy recorded SNI `p0c2a.test` **without terminating TLS** |
| A4 | Proton/Wine WinHTTP | none | direct | Rejected. `0x80072f7d` (`ERROR_WINHTTP_SECURE_FAILURE`); observer: `client_sent_request=false`, `rejected_after_handshake` |
| A5 | Proton/Wine WinHTTP | CA in prefix store, **IP URL** | direct | Rejected. `0x80072f7d` — see the IP-address trap in `trust_store_matrix.md` |
| A5c | Proton/Wine WinHTTP | CA in prefix store, **hostname URL** | direct | **Accepted.** HTTP 200; observer: SNI `localhost`, `accepted_certificate` |

A3 is the important one for method: the proxy produced useful metadata (**which host, which SNI**)
while decrypting nothing. That is the mode every later stage ran in.

## Explicit-proxy mechanisms (Proton/Wine WinHTTP)

Each mechanism was aimed at a **distinct** non-loopback documentation address so the results could
not be confused with one another.

| Mechanism | Target | Proxy used? |
|---|---|---|
| `WinHttpRequest.SetProxy` (COM) | `192.0.2.1` | No |
| WinINET `HKCU\…\Internet Settings` `ProxyEnable`/`ProxyServer` | `192.0.2.2` | No |
| **`http_proxy` / `https_proxy` environment variables** | `192.0.2.3` | **Yes** |

Two methodological notes, both of which initially produced wrong answers:

1. **Loopback cannot be used to test proxying.** WinHTTP bypasses the proxy for loopback
   destinations, and Wine did not honour the `<-loopback>` bypass-override token. A loopback test
   looks exactly like "the proxy was ignored".
2. **A dead listener looks like a bypassed proxy.** An earlier round of these tests recorded "no
   CONNECT" for all three mechanisms. The proxy had in fact failed to start with
   `EADDRINUSE` because a previous instance still held the port, so nothing was listening. The
   results above are from a re-run against a confirmed-live proxy, and the earlier conclusion was
   discarded.

## Stage C — MCC through the explicit proxy

MCC was launched from Steam with `http_proxy`/`https_proxy` set via Launch Options, with the proxy
in **tunnel mode** (no TLS termination anywhere).

**MCC honoured the proxy.** Seven `CONNECT` requests arrived from MCC:

| Host | Exclusion status | Action taken |
|---|---|---|
| `login.live.com` | excluded | `blind_tunnel_excluded` |
| `login.microsoftonline.com` | excluded | `blind_tunnel_excluded` |
| `sisu.xboxlive.com` | excluded | `blind_tunnel_excluded` |
| `title.mgt.xboxlive.com` | excluded | `blind_tunnel_excluded` |
| `api.epicgames.dev` (×2) | excluded | `blind_tunnel_excluded` |
| `modules-cdn.eac-prod.on.epicgames.com` | excluded | `blind_tunnel_excluded` |

**All 7 were on the hard-exclusion list, and all 7 were blind-tunnelled. Zero connections were
decrypted.** Not one byte of identity, token, or entitlement traffic was terminated, and no header
value or body was read. The exclusion is enforced *before* any mode branch in the proxy, so this
was structural rather than a filter that happened to hold.

**Observed side effect:** with traffic routed through the proxy, MCC reported
*"Error encountered while signing into Xbox Live"*. The cause was not diagnosed — doing so would
have meant inspecting exactly the identity traffic this rung forbids. What can be said is narrow
and factual: routing MCC's traffic through an explicit proxy is **detectable in its behaviour**,
and the earliest traffic MCC emits is authentication, not title services.

## Stage D — not performed

Stage D was conditional on explicit proxying **not** reaching MCC. It did reach MCC, so Stage D was
not required and was not run: no hostname was redirected, `/etc/hosts` was never modified, and no
DNS override was created (`rollback_verification.txt` §5).

## Certificate acceptance by MCC — unresolved

**Whether MCC accepts a locally trusted CA, rejects it, or pins certificates is UNRESOLVED, and
this rung cannot answer it.**

Every connection MCC made through the proxy was to an excluded host and was therefore blind-tunnelled
by design. No MCC connection was ever TLS-terminated with the test CA, so there was no opportunity
to observe acceptance, rejection, or pinning. This is a direct and expected consequence of the
exclusion list, not a tooling failure — and the alternative (terminating identity traffic to find
out) is precisely what the rung prohibits.

What would resolve it is an MCC connection to a **non-identity, non-entitlement** title service —
for example a read-only settings or content-metadata endpoint — reached while the proxy is in
terminate mode for that host alone. In this session MCC never got that far: sign-in failed first,
so no title-service request was attempted.

## Interpretation boundary

Established here: explicit-proxy support for a native Linux client, for a Proton/Wine WinHTTP
client (environment variables only), and for MCC itself; the certificate stores that govern each;
and that granting Wine trust needs no administrative privilege.

**Not** established: authentication bypass, token forgery, server compatibility, endpoint schemas,
replacement-service correctness, native Windows behaviour, whether MCC pins certificates, or
whether any of this generalises beyond the hosts observed. One client honouring `http_proxy` does
not prove every MCC subsystem uses the same HTTP or TLS stack — the P0-C1 module list shows both
`winhttp.dll` and `wininet.dll` loaded, and those are different stacks with different proxy rules.
