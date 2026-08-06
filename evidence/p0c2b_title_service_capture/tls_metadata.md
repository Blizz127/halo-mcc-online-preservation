# P0-C2B TLS metadata

**No TLS session was terminated during this rung, so there is no certificate-exchange metadata to
report.** This file exists to record that fact explicitly rather than leave the reader wondering
whether it was omitted.

## What was observed

The proxy ran in **tunnel mode** for the whole rung. Every `CONNECT` was relayed as opaque bytes:
the proxy never held a TLS session with MCC, never presented a certificate, and never saw a
plaintext byte.

| Metric | Value |
|---|---|
| CONNECT requests from MCC | 7 |
| Connections TLS-terminated | **0** |
| Connections with a recorded `tls_result` | **0** |
| Certificates presented by the proxy | **0** |
| Temporary CAs generated or installed | **0** |
| Request/response bodies read | **0** |

Because every host MCC contacted was on the hard-exclusion denylist, the proxy did not even parse
the TLS ClientHello for SNI — excluded hosts skip that inspection step entirely, so `sni` is `null`
for all seven records. The destination hostname is known from the `CONNECT` target line, which is
plaintext by protocol design and is not extracted from the TLS session.

## Tunnel throughput (content-free)

Byte counts are recorded because they distinguish "the tunnel failed" from "the tunnel worked and
something else failed" without revealing anything about content:

| Host | CONNECTs | Bytes relayed |
|---|---:|---:|
| `api.epicgames.dev` | 2 | 62,852 |
| `title.mgt.xboxlive.com` | 1 | 28,358 |
| `sisu.xboxlive.com` | 1 | 20,768 |
| `login.live.com` | 1 | 11,528 |
| `modules-cdn.eac-prod.on.epicgames.com` | 1 | 6,209 |

All five hosts carried substantial bidirectional traffic. The tunnels were therefore **working** —
they were not closing early, starving the exchange, or failing to relay. Whatever caused sign-in to
fail happened at a layer this rung deliberately cannot see.

## What would have been recorded, had Stage B run

For the single allowlisted host only, and only after MCC reached the main menu:

- TLS version and negotiated cipher suite
- whether MCC accepted the temporary CA, or which alert it sent on rejection
- the SNI presented on that one connection
- certificate chain **metadata** (subject, issuer, validity, SHA-256 fingerprint) — never a key

None of this exists, because Stage B did not run.

## Certificate acceptance by MCC — still unresolved

`E-P0C2A-005` recorded MCC's certificate-acceptance and pinning behaviour as **unresolved**. This
rung does not change that, and for the same structural reason: no MCC connection was ever
TLS-terminated, so there was again no opportunity to observe acceptance, rejection, or a pinning
alert.

Two rungs have now ended without answering it. That is not a tooling gap — it is a consequence of
MCC never getting past authentication while proxied, and of authentication being exactly what these
rungs are forbidden to decrypt.
