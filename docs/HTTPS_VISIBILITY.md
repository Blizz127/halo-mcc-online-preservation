# HTTPS visibility and trust paths

What is observable, and by what mechanism, for the retail MCC client on Bazzite/Steam/Proton. Every
statement cites an evidence ID resolving to `evidence/p0c2a_https_visibility/`; that directory is
authoritative and wins if this summary drifts.

**Platform scope:** Linux/Proton only. Native Windows behaviour is unobserved (P0-B2 unstarted) and
must not be assumed identical — a different OS means a different TLS stack and different proxy rules.

**Nothing here decrypts identity traffic.** Microsoft account, Xbox authentication, XSTS, MPSD,
entitlement, purchase, Steam, PlayFab, and Epic hosts are on a hard exclusion list and were
blind-tunnelled without termination.

## Proxy support by client

| Client | Mechanism | Works | Evidence |
|---|---|---|---|
| Native Linux (OpenSSL) | explicit proxy | **Yes** | `E-P0C2A-001` |
| Proton/Wine WinHTTP | `WinHttpRequest.SetProxy` (COM) | No | `E-P0C2A-002` |
| Proton/Wine WinHTTP | WinINET `HKCU` `ProxyEnable`/`ProxyServer` | No | `E-P0C2A-002` |
| Proton/Wine WinHTTP | **`http_proxy` / `https_proxy` env** | **Yes** | `E-P0C2A-002` |
| **MCC itself** | **`http_proxy` / `https_proxy` env** (Steam Launch Options) | **Yes** | `E-P0C2A-004` |

WinINET and WinHTTP are separate stacks with separate proxy configuration; setting one does not
affect the other. MCC loads **both** `winhttp.dll` and `wininet.dll`, so proxy behaviour proven for
one stack does not automatically hold for the other.

## Certificate stores

| Store | Governs | Admin needed |
|---|---|---|
| `/etc/pki/ca-trust/source/anchors` + `update-ca-trust` | native Linux clients | **Yes** |
| **Proton prefix Root store** — `HKLM\Software\Microsoft\SystemCertificates\Root\Certificates\<SHA1>` | **Wine/Proton clients, incl. MCC** | **No** |
| `~/.pki/nssdb` | browsers only | No |

The MCC prefix has an **independent** Root store (167 pre-existing entries, written at prefix
creation). Trust granted there affects that prefix only — not the host, not other prefixes — which
makes it the least invasive place to grant trust for a bounded test. See `E-P0C2A-003`.

## Two traps that produce confidently wrong conclusions

Both of these produced wrong answers during this rung before being caught:

1. **Wine's WinHTTP rejects certificates presented for a bare IP address**, even with a matching IP
   SAN and the CA trusted. Test with a **hostname**, or you will conclude the trust store is ignored
   when it is working fine.
2. **WinHTTP bypasses the proxy for loopback destinations**, and Wine does not honour the
   `<-loopback>` bypass-override token. A loopback target makes every proxy mechanism look ignored.
   Use a non-loopback address (RFC 5737 documentation ranges work without touching anything real).

A third, non-TLS trap: under **TLS 1.3 the server finishes its handshake before the client validates
the certificate**, so a server-side "handshake completed" is *not* client acceptance. The reliable
signal is whether the client then sends a request.

## What remains unknown

- **Whether MCC accepts a locally trusted CA, rejects it, or pins certificates — UNRESOLVED**
  (`E-P0C2A-005`). Every MCC connection observed was to an excluded host and was therefore never
  TLS-terminated, so there was no opportunity to observe acceptance or a pinning alert. Answering it
  needs an MCC connection to a **non-identity** title service, which this session never reached
  because sign-in failed first.
- **Why sign-in failed while proxied.** Observed, not diagnosed — diagnosing it would have required
  inspecting the identity traffic the rung forbids. It is known to be **transient**: after rollback
  (Launch Options cleared, Steam fully restarted) sign-in succeeded and MCC ran normally end to end,
  so nothing about the client, prefix, or account was persistently changed (`E-P0C2A-006`).
- Everything in the P0-C1 interpretation boundary still stands: no schemas, no token formats, no
  claim that a replacement service would be accepted, no native-Windows behaviour.

## Reproducing

```bash
# local test CA (reserved test domains only; keys stay in ignored scratch, mode 0600)
python3 tools/interception/linux/local_ca.py <scratch>/ca --hostname p0c2a.test

# local TLS observer - records SNI and client verdict, never bodies
python3 tools/interception/linux/tls_observer.py --cert <scratch>/ca/server.crt \
        --key <scratch>/ca/server.key --port 8443 --mode stage_a

# explicit proxy - tunnel mode decrypts nothing; excluded hosts always tunnel
python3 tools/interception/linux/metadata_proxy.py --port 8080 --mode tunnel --log <scratch>/proxy.json

# grant/revoke trust inside a Proton prefix (no admin required; revocation is verified)
python3 tools/interception/linux/wine_trust.py install|check|remove \
        --prefix <MCC_PROTON_PREFIX> --proton-wine <PROTON>/files/bin/wine --cert <scratch>/ca/ca.crt
```

The exclusion list lives in `tools/interception/linux/exclusions.py` and fails closed on an unknown
or empty host. Change it only with a corresponding test in `tests/test_interception_linux.py`.
