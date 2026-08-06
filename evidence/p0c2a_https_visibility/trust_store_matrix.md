# P0-C2A trust-store matrix

Which certificate stores govern TLS trust for each client in the Bazzite → Steam → Proton → Wine →
MCC chain, what privileges each requires, and exactly how each change is reversed.

Only SHA-256 fingerprints and SHA-1 thumbprints are recorded. No private key material appears in
this repository, and none was ever copied out of the ignored local scratch directory.

## Stores identified

| Store | Path | Governs | Admin required | Used in this rung |
|---|---|---|---|---|
| Bazzite host system anchors | `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust` | Native Linux clients (OpenSSL/GnuTLS) | **Yes** | **No** — deliberately avoided |
| Host extracted bundle | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` (`/etc/ssl/certs/ca-certificates.crt` symlinks here) | Native Linux clients | Yes (generated) | Read only |
| Per-process explicit CA | `SSLContext.load_verify_locations(cafile=…)` | One process only | No | Yes (Stage A Linux client) |
| **MCC Proton prefix Root store** | `HKLM\Software\Microsoft\SystemCertificates\Root\Certificates\<SHA1>` inside the prefix registry | **Wine/Proton clients, including MCC** | **No** | **Yes** |
| NSS user store | `~/.pki/nssdb` | Browsers (Firefox/Chrome family) | No | No — not consulted by Wine |

## The prefix has its own independent Root store

The MCC Proton prefix carries **167** pre-existing `SystemCertificates` entries in its own
registry, written when the prefix was created. It is independent of the host store: trust granted
there affects only that prefix, and neither the host nor any other prefix.

This is the least invasive place to grant trust for a test, and it is the one the rung used:

- it needs **no administrative privileges**,
- it cannot affect the host system or any other application,
- it is removed by deleting a single registry key, and the removal is verifiable.

## Observed trust behaviour

| Client | CA state | Outcome |
|---|---|---|
| Native Linux (Python/OpenSSL) | not trusted | Rejected — `unable to get local issuer certificate`; server observed TLS alert `TLSV1_ALERT_UNKNOWN_CA` |
| Native Linux | CA supplied explicitly | Accepted — TLS 1.3, HTTP 200 |
| Proton/Wine WinHTTP | not trusted | Rejected — `0x80072f7d` (`ERROR_WINHTTP_SECURE_FAILURE`) |
| Proton/Wine WinHTTP | CA installed in prefix Root store, **hostname** URL | **Accepted** — HTTP 200 |
| Proton/Wine WinHTTP | CA installed in prefix Root store, **bare IP** URL | Rejected — `0x80072f7d`, despite a matching IP SAN |

### The IP-address trap

The last two rows matter more than they look. Wine's WinHTTP rejected the certificate when the URL
used a **bare IP address**, even though the leaf carried a matching `IP:127.0.0.1` SAN and the CA
was trusted in the prefix. Testing only with an IP URL would have produced the confident and
completely wrong conclusion that *"Proton ignores the prefix trust store"*. The store works; the
address form was the variable. Any future rung testing Wine TLS trust should use a hostname.

## Privilege summary

- **No administrative privilege was used or required** for any trust change in this rung.
- The host system store was never modified. `/etc/pki/ca-trust/source/anchors/` is not writable
  by the operator account, and adding to it would have affected every application on the machine
  rather than one prefix — the opposite of what a bounded test wants.

## Rollback

Three test CAs were installed into the prefix Root store during the rung and all three were
removed. Rollback was verified against the prefix registry file directly, not merely by trusting
the removal tool's own exit status:

| SHA-1 thumbprint | Purpose | Removed | Verified absent |
|---|---|---|---|
| `0861AC7D6B615744E491C29C9778B6C0CB8D3CD9` | name-constrained CA | Yes | Yes |
| `6EE4BF533FA8605F8A978460B962F1F4A0B48137` | CA without name constraints (diagnostic) | Yes | Yes |
| `380367A4E74B790F7D4F08314C66222F3CCCDB89` | CA for the `localhost` leaf | Yes | Yes |

Exact reversal commands:

```bash
python3 tools/interception/linux/wine_trust.py remove \
  --prefix  <MCC_PROTON_PREFIX> \
  --proton-wine <PROTON>/files/bin/wine \
  --thumbprint <SHA1>
```

`remove` re-queries the registry afterwards and reports `verified_absent`, so a failed rollback is
visible rather than silent. Full results are in `rollback_verification.txt`.

A separate, unrelated change — the WinINET `ProxyEnable`/`ProxyServer` registry values — was also
made and reverted during proxy-mechanism testing; its pre-test state (`ProxyEnable=0x0`,
`ProxyServer` absent) was recorded before the change and restored exactly.

## Defence in depth on the test CA itself

Independent of rollback, the test CA was built so that a *forgotten* copy would be close to
useless:

- **2-day validity**, so it expires on its own.
- **`NameConstraints` limited to `p0c2a.test` and `127.0.0.0/8`**, so where the extension is
  honoured it cannot vouch for any real host. Whether Wine enforces name constraints was **not**
  isolated by this rung and remains unresolved — the constrained and unconstrained CAs behaved the
  same, but both were confounded by the IP-address issue above.
- **`pathlen:0`**, so it cannot issue subordinate CAs.
- Certificates were only ever issued for reserved test names (`.test`, RFC 6761) and `localhost`;
  the generator refuses anything else.
