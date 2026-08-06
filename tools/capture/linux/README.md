# Linux passive connection-capture tooling

Read-only tooling for the P0-C rung (`docs/ROADMAP.md` §P0-C), scoped to **passive**
observation: what the client contacts, when, over which protocol, owned by which process.

Nothing here decrypts TLS, installs a certificate, configures a proxy, redirects DNS, patches
the client, injects a library, or contacts a service on the client's behalf. The modules only
read files and run read-only system queries (`ss`, `ip`, `resolvectl`, `tailscale status`).

## Modules

- `capture_env.py` — capture-interface discovery, tool versions, and a **capture-readiness
  probe** that reports whether unprivileged capture actually works and why not. On an
  ostree-based host `/usr` is read-only, so `setcap` cannot be applied to `tcpdump` in place;
  the probe records that fact rather than letting a rung assume pcap evidence is available.
- `dns_monitor.py` — timestamped `resolvectl monitor` runner and parser. This is the **primary**
  DNS source, not pcap: when DNS is routed through a VPN resolver it is not necessarily visible
  as plaintext UDP/53 on the wire, and the resolver's own view is structured (name, type,
  status, answers). `resolvectl monitor` emits no timestamps, so the runner stamps each line on
  arrival — these are observation times, not resolver-internal times.
- `socket_poller.py` — repeated `ss -tunpH` sampling for socket→process attribution, aggregated
  into flows with `first_seen`/`last_seen`/`sample_count`. Sampling is lossy by construction: a
  connection opened and closed entirely between two samples is never seen, and a flow with
  `sample_count == 1` is weak timing evidence. Both limits are reported, not hidden.
- `pcap_parse.py` — pure-Python pcap reader (no `tshark`/`scapy` on this host). Handles
  `LINKTYPE_ETHERNET`, `LINKTYPE_LINUX_SLL`, and `LINKTYPE_LINUX_SLL2` — `tcpdump -i any` on
  libpcap ≥ 1.10 writes SLL2, and misreading it would silently drop every packet. Extracts
  packet timestamps, L3/L4 addressing, DNS question names, and TLS ClientHello SNI. It does not
  reassemble TCP streams or decode application payloads, so no HTTP body, header, cookie, or
  credential can be extracted by it.
- `net_sanitize.py` — address and network-identity redaction, layered on
  `tools/inventory/linux/sanitize.py`. Every value is derived from the live host, so a real
  address never needs to appear in a command line or in source.
- `build_topology.py` — joins DNS, socket, and pcap evidence; applies the privacy filter and the
  classification rules; emits the CSV inventories.

## Redaction policy

| Address class | Treatment |
|---|---|
| This host's own addresses | `<LOCAL_IPV4>` / `<LOCAL_IPV6>`, or `<TAILSCALE_IPV4>` / `<TAILSCALE_IPV6>` |
| Other private / CGNAT / link-local | `<PRIVATE_HOST_n>` (LAN neighbours and VPN peers are other devices, not MCC evidence) |
| Loopback | kept — universal, not identifying |
| Public destinations | **kept** — a destination server's address is the evidence this rung exists to record |

Also redacts the VPN search domain and VPN device hostnames. `<PRIVATE_HOST_n>` numbering is
stable within a run; the mapping is never committed, so the placeholders are not reversible from
the repository.

## Privacy filter (why the committed inventory is smaller than what was observed)

`resolvectl monitor` sees DNS for the **whole host**, including unrelated applications. Only
flows attributed to a target process role — the MCC game, its launcher, the Proton/Wine layer,
or the Steam client — are retained in committed evidence. Traffic belonging to other processes
is **counted and reported as a total, never enumerated**, so the committed files cannot become a
record of unrelated browsing. Reducing background noise before a capture (closing browsers and
chat clients) both sharpens the evidence and shrinks what has to be filtered.

## Classification rules

A `Confirmed` classification requires **both**:

1. process attribution to a relevant role, **and**
2. a registrable-domain suffix match against a known service family,

with the supporting reason recorded next to the verdict. A family match with no process
attribution is at most `Likely classification requiring verification`. **No endpoint is ever
confirmed from a hostname alone** — matching is on registrable suffix, so a lookalike such as
`xboxlive.com.attacker.invalid` does not match, and reverse DNS is never used for attribution
(a PTR record describes address ownership, not application purpose).

## Raw captures

Raw pcap/pcapng files stay in a local scratch directory **outside the repository** and are never
committed; `.gitignore` covers `*.pcap`/`*.pcapng` as a second layer. Evidence records a
SHA-256 hash and a sanitized placeholder path for each raw capture so it can be referenced
without being distributed.

Captures for this rung are taken with a small `--snapshot-length`, which truncates packets on
disk at capture time: request and response bodies physically are not written to the file. A
ClientHello truncated past its SNI extension yields `None` rather than a partial guess.
