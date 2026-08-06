# P0-C1 report: Bazzite client bootstrap and passive connection topology

Scope: map the observable Steam → Proton → Microsoft/Xbox → MCC service connection sequence for
the retail build already banked in `evidence/p0b1_bazzite_proton_build_bank/` (appid `976730`,
buildid `19905945`), using **passive metadata collection only**.

Nothing in this rung decrypted TLS, installed a certificate, configured a proxy, redirected DNS,
patched the client, injected a library, bypassed authentication, or implemented a replacement
service. No session cookie, OAuth code, authorization header, XSTS token, bearer token, account
email, gamertag, XUID, or Steam ID was extracted, and the authentication cache was never opened.

Halo Infinite is not used as evidence anywhere below.

## Method and its limits

Three independent collectors, all read-only:

| Source | Tool | What it gives | What it cannot give |
|---|---|---|---|
| DNS | `resolvectl monitor`, timestamped on arrival | Query name, type, status, answer addresses | No process attribution; no timestamps of its own |
| Sockets | `ss -tunpH` sampled every 0.5s | Peer address/port **and owning process** | Misses connections shorter than the sample interval |
| Packets | `tcpdump -i any -s 400`, parsed by `tools/capture/linux/pcap_parse.py` | Exact packet timing, TLS SNI, short-lived UDP | No process attribution |

**These three disagree in ways that matter, and the disagreement is itself a finding** — see
Claim 5, where socket sampling reported zero contact with a service that the packet record shows
was contacted 1,366 times.

Privileged capture was not available unprivileged on this host: `/usr` is read-only (ostree), so
`setcap` cannot be applied to `tcpdump` in place, and `sudo` requires a password that an
automated shell cannot supply. The operator therefore started one bounded capture manually via
`tools/capture/linux/run_capture.sh`; every other step ran unprivileged.

### Known method limitations

1. **Socket sampling is lossy.** A 0.5s interval cannot see a UDP probe that opens and closes
   between samples. Claim 5 exists because of this.
2. **Background applications were left running.** A browser and chat client stayed open during
   capture, so the raw pcap contains unrelated traffic. It is never committed, and the
   process-attribution filter excludes that traffic from every committed inventory
   (323 of 586 flows excluded on this basis).
3. **DNS caching distorts first-contact ordering.** A name resolved in an early scenario is not
   re-resolved later, so `connection_timeline.md` marks negative offsets as "first seen earlier",
   not "unused at launch".
4. **Scenario C2 was lost to a timing race** and is recorded `void` in `capture_index.json`
   rather than silently dropped: a fixed 180s window expired while the operator was reading the
   prompt, so no launch occurred inside it. It was replaced by **C2b**, a clean cold launch with
   collectors already running continuously. The collectors were switched to continuous operation
   with timestamp markers precisely so scenario boundaries stop racing operator response time.
5. **C3 (interactive sign-in) did not occur** — see Claim 3. This is a finding, not a gap in
   coverage.

## Scenarios completed

| ID | Scenario | Result |
|---|---|---|
| C1 | Baseline idle, Steam up, MCC closed | Captured (60.1s) |
| C2 | MCC cold launch, first attempt | **Void** — fixed window expired before launch |
| C2b | MCC cold launch, continuous collectors | Captured (91.5s) |
| C3 | Microsoft/Xbox interactive sign-in | **Did not occur** — identity was established from cache (Claim 3) |
| C4 | Main-menu initialization | Covered inside C2b and C5 |
| C5 | Halo: Reach and online-menu navigation | Captured (211.7s) |
| C6 | Normal shutdown | Captured (101.3s) |

## Claim 1 — MCC-specific title services are a distinct, observable service layer

**Claim:** MCC contacts a dedicated `*.svc.halowaypoint.com` service layer, distinct from both
Steam and generic Xbox Live. Thirteen endpoints were confirmed, including
`settings.svc.halowaypoint.com`, `entitlements.svc.halowaypoint.com`,
`halostats.svc.halowaypoint.com`, `banprocessor.svc.halowaypoint.com`,
`notification.svc.halowaypoint.com`, `telemetry.svc.halowaypoint.com`, and
`gamecms-hacs.svc.halowaypoint.com`. Each resolves through a CNAME chain to a named Azure
dispatcher (e.g. `s3p-settings-eus-dispatcher-production.eastus.cloudapp.azure.com`,
`s3p-halostats-dispatcher-production.eastus2.cloudapp.azure.com`), which exposes the backend
service decomposition by name. `mcc-production.azurefd.net` is an additional title-specific Azure
Front Door hostname.

**Evidence IDs:** `E-P0C1-001` (`domain_inventory.csv`, rows classified
`Confirmed MCC/Halo title service`), `E-P0C1-002` (`process_socket_map.md` §`mcc_game`)

**Reproduction:** Run the collectors in `tools/capture/linux/` across a cold launch; join socket
peers to DNS answers with `build_topology.py`.

**Counter-evidence / limits:** Confirmation here means *the MCC game process held a socket to an
address that DNS resolved from that name*. It does **not** establish what the service does, its
API shape, or its authority — `settings.svc.halowaypoint.com` is named suggestively but this rung
observed no payload whatsoever. The dispatcher hostnames are infrastructure naming, not a
documented architecture.

**Confidence:** High for existence, naming, ownership by the game process, and transport
(TCP/443). None for behavior or schema.

**Authorized next action:** None here. Any schema question belongs to a later rung.

## Claim 2 — Identity precedes title services, with a distinct token-exchange step

**Claim:** In the clean cold launch (C2b), the bootstrap order was: anti-cheat module delivery
(+41.7s) → Xbox title management (+51.7s) → **Microsoft identity `login.live.com` (+70.7s)** →
**Xbox token exchange `xsts.auth.xboxlive.com` (+70.9s)** → Xbox platform services (+71.4s to
+71.6s) → Halo title services (+72.2s onward) → TURN relays (+73.1s) → entitlements and ban
processing (+87.2s). No Halo title service was resolved before identity, and the token-exchange
endpoint followed the identity endpoint within ~0.2s.

**Evidence IDs:** `E-P0C1-003` (`connection_timeline.md`), `E-P0C1-002`

**Counter-evidence / limits:** This is **ordering of first DNS resolution**, not proof of causal
dependency; a client could resolve names in any order. The ~0.2s gap between `login.live.com` and
`xsts.auth.xboxlive.com` is consistent with a token exchange following sign-in, but no token,
header, or payload was observed and none may be inferred. `docs/ARCHITECTURE_HYPOTHESES.md` H-003
concerns the *token format*, which this rung cannot and does not address.

**Confidence:** High for the observed ordering. None for causality or token semantics.

## Claim 3 — Identity was established non-interactively from a cached session

**Claim:** Across **two independent launches**, MCC reached the main menu with no
Microsoft/Xbox sign-in prompt. The operator was asked to sign in and reported that no prompt
appeared; the menu was reachable and online status displayed as connected. This differs from
`evidence/p0b1a_interactive_launch/` (`E-P0B1A-005`), where sign-in was interactive on a colder
profile state. `login.live.com` and `xsts.auth.xboxlive.com` were still contacted on the silent
launch, so the client still performed a network identity step — it simply required no user input.

**Evidence IDs:** `E-P0C1-004` (`connection_timeline.md`, C2b rows), operator observation
recorded in `capture_index.json`

**Counter-evidence / limits:** The mechanism was **not** investigated. Inspecting the
authentication cache is explicitly outside this rung's boundary and was not done, so "cached
session" describes the observed behavior, not a verified storage mechanism. Because sign-in never
prompted, **scenario C3 produced no interactive sign-in traffic**; the redirect chain a real
sign-in would produce remains unobserved.

**Confidence:** High that no interactive prompt occurred on two launches. None for the caching
mechanism, credential lifetime, or what would happen on expiry.

**Authorized next action:** A later rung wanting C3 would need a deliberate sign-out — a state
change requiring its own authorization.

## Claim 4 — MPSD is contacted by the MCC process during menu-only activity

**Claim:** `sessiondirectory.xboxlive.com` — the Xbox Multiplayer Session Directory — was
resolved and held as a TCP/443 socket **owned by the MCC game process**, during menu navigation
with no match started, no invite sent, and no matchmaking entered.

**Evidence IDs:** `E-P0C1-005` (`domain_inventory.csv`, `sessiondirectory.xboxlive.com`),
`E-P0C1-002` (`process_socket_map.md` §`mcc_game`, 71 samples)

**Counter-evidence / limits:** This shows MPSD is **contacted**, not that it is authoritative for
any MCC mode, nor what session documents were exchanged — the connection is TLS and no payload
was observed. `docs/ARCHITECTURE_HYPOTHESES.md` H-004 asks whether MPSD is *the authoritative
session directory for every target mode*; contact during menus is consistent with that but far
short of proving it. H-004 therefore remains **Unproven** and is not advanced by this rung.

**Confidence:** High that the game process connected to MPSD. None for MPSD's role or authority.

## Claim 5 — QoS probing to 15 Azure regions over UDP/3075, invisible to socket sampling

**Claim:** The client resolved `mpsqosprod.<region>.cloudapp.azure.com` across **15 Azure
regions** (151 DNS transactions) and sent **1,366 UDP packets on port 3075** to those addresses —
244 during the cold launch (C2b) and 630 during menu navigation (C5), and **zero during idle
baseline (C1) and shutdown (C6)**.

**Socket sampling reported zero contact with every one of these 15 addresses.** The probes are
short-lived UDP exchanges that fall entirely between 0.5s samples. Only the packet record shows
them.

**Evidence IDs:** `E-P0C1-006` (packet analysis over the raw capture hashed in
`capture_index.json`), `E-P0C1-003` (region list in DNS)

**Counter-evidence / limits:** Attribution rests on **destination-address correlation** (the
addresses were resolved from `mpsqosprod` names during the MCC session), not on process
ownership, because pcap carries no process information and `ss` never saw these sockets. That is
weaker than the socket-attributed claims above and is stated as such. Region-latency probing is
*consistent with* selecting a regional server, which bears on H-008, but no allocation, no server
assignment, and no match were observed — H-008 remains **Unproven**.

This claim is also the concrete reason the report treats socket sampling as lossy: a rung relying
on `ss` alone would have concluded, wrongly, that no QoS traffic existed.

**Confidence:** High that the traffic occurred, on that port, in those phases. Medium for
"this is MCC's" (address correlation, not process ownership). None for its purpose.

## Claim 6 — Halo-operated TURN relays are resolved and probed during menu-only activity

**Claim:** The client resolved Halo-operated TURN/STUN relay hostnames —
`COTURN.HW-USW-PROD.halowaypoint.com`, `COTURN.HW-USW01-PROD.halowaypoint.com`,
`turn-mcc.trafficmanager.net`, `turn-mcc01.trafficmanager.net`, and
`coturn-hw-ussc0{2,3,4}-prod.southcentralus.cloudapp.azure.com` (5 distinct addresses, US-West and
South-Central US) — at +73.1s in the cold launch, and sent **32 UDP packets to them on port
3478**, the registered STUN/TURN port, during menu-only activity.

**Evidence IDs:** `E-P0C1-007` (packet analysis; DNS names in `connection_timeline.md`)

**Counter-evidence / limits:** This is the single most easily over-read finding in the rung, so
its limits are stated plainly:

- It shows STUN/TURN-port traffic to relays **named** for Halo. It does **not** show ICE
  candidate exchange, a negotiated peer path, or any gameplay session — no match was started.
- 32 packets is a small volume consistent with candidate gathering or a keep-alive, and this rung
  cannot distinguish those.
- Of 586 total UDP packets on ports 3478/3479 in the capture, only these 32 are attributable to
  MCC. The remainder went to addresses with **no DNS name and no process owner**, in ranges
  belonging to this host's VPN relay infrastructure, which independently uses STUN. Per
  `docs/EVIDENCE_POLICY.md`, address ownership is supporting context only, so that traffic is
  recorded as **not attributable to MCC** rather than assigned to either party
  (`unresolved_endpoints.md` §2).

H-011 (ICE/STUN-negotiated UDP path) and H-005 both remain **Unproven**: relay endpoints existing
and being probed is a necessary condition for those hypotheses, not a demonstration of them.

**Confidence:** High that Halo-named TURN relays were resolved and received UDP/3478 traffic.
None for ICE negotiation, transport selection, or gameplay path.

## Claim 7 — Anti-cheat module delivery occurs even though no EAC process runs

**Claim:** `modules-cdn.eac-prod.on.epicgames.com` was contacted at +41.7s, attributed to the
**MCC launcher** process, and `api.epicgames.dev` was contacted by the game process. This occurs
on the normal launch path, on which `evidence/p0b1a_interactive_launch/` (`E-P0B1A-004`) recorded
**no EAC process and no EAC-named loaded module** at any checkpoint.

**Evidence IDs:** `E-P0C1-008` (`domain_inventory.csv`, `process_socket_map.md`)

**Counter-evidence / limits:** Contacting an anti-cheat module CDN is not proof that anti-cheat
was loaded, initialized, or enforced. The two observations are consistent — modules may be
fetched, cached, or validated without a resident process appearing at the checkpoints sampled —
but this rung neither resolves nor claims to resolve that. It is recorded because a future rung
examining EAC should know both facts exist together. H-012 is unchanged.

**Confidence:** High for the network contact and its process attribution. None for anti-cheat
state.

## Endpoint classification summary

| Classification | Count |
|---|---:|
| Confirmed Xbox platform | 14 |
| Confirmed MCC/Halo title service | 13 |
| Confirmed Steam | 4 |
| Confirmed Microsoft identity | 1 |
| CDN/telemetry | 4 |
| Likely, requiring verification | 3 |
| Unknown | 34 |

A `Confirmed` verdict required **both** process attribution to a relevant role **and** a
registrable-suffix match against a known service family, with the reason recorded per row in
`domain_inventory.csv`. A family match without process attribution is at most `Likely`.
Registrable-suffix matching means a lookalike such as `xboxlive.com.attacker.invalid` does not
match, and reverse DNS was never used for attribution.

The 34 `Unknown` endpoints are mostly loopback IPC, LAN device discovery, and target-process
sockets whose peer name was never observed in DNS; they are enumerated in
`unresolved_endpoints.md` rather than guessed at.

## Privacy handling

`resolvectl monitor` observes DNS for the entire host. Committed evidence therefore retains
**only** flows attributed to the MCC game, its launcher, the Proton/Wine layer, or the Steam
client. Traffic belonging to other applications is counted and reported as a total
(**323 of 586 flows excluded**) and never enumerated, so no committed file becomes a record of
unrelated browsing.

Redaction applied by `tools/capture/linux/net_sanitize.py`: `<HOME>`, `<STEAM_LIBRARY>`,
`<MCC_INSTALL_ROOT>`, `<MCC_PROTON_PREFIX>`, `<ACCOUNT_IDENTIFIER_REDACTED>`, `<LOCAL_IPV4>` /
`<LOCAL_IPV6>`, `<TAILSCALE_IPV4>` / `<TAILSCALE_IPV6>`, `<PRIVATE_HOST_n>` for other
private/CGNAT/link-local addresses, plus the VPN search domain and VPN device hostnames. Public
destination addresses are **kept**, because a destination server's address is the evidence this
rung exists to record and is not personal data.

The raw capture is **not committed**: it stays in local scratch outside the repository, is
recorded only by SHA-256 and a placeholder path in `capture_index.json`, and was taken with a
400-byte snaplen so request and response bodies were truncated at capture time and physically
cannot be in the file.

## Defects found and fixed during this rung

Three tooling defects were found by their symptoms and fixed, each with a regression test:

1. **DNS collector hung on idle windows.** `for line in proc.stdout` blocks until a line arrives,
   so a window with no DNS never reached the deadline check. Fixed with a watchdog timer that
   terminates the child at the deadline. Verified: an 8s idle window now returns in ~9s instead
   of running to the hard timeout.
2. **Socket poller wrote results only at exit.** A long capture that was interrupted — or merely
   inspected mid-run — yielded nothing. Fixed with periodic checkpointing. Verified mid-run.
3. **Process attribution silently dropped the game's own sockets.** `ss` reports the kernel's
   `comm`, which is the *main thread* name, and `MCC-Win64-Shipping.exe` renames its main thread
   to `MAIN_THREAD` after startup. Role matching on `comm` therefore failed for exactly the
   process this rung most needed to attribute; some sockets survived only incidentally because
   `wineserver` co-owned them. Fixed by resolving roles from process **argv** by PID, with
   `comm` as fallback, and by matching wrapper markers first so the Steam→Proton→game chain is
   not mislabelled as the game. This was the most consequential of the three: it would have
   quietly removed MCC's traffic from the committed inventory rather than failing loudly.

## Interpretation boundary

This rung establishes observed domains, connection timing, protocols and ports, process ownership
where proven, whether traffic appeared before/during/after sign-in, and that UDP transport
(QoS/3075, TURN/3478) **does** appear during menu-only activity.

It does **not** establish plaintext API schemas, token formats, whether server-side validation can
be bypassed, whether a local replacement service would be accepted, whether DNS redirection is
sufficient, whether TLS certificate validation can be altered, whether native Windows behaves
identically, or whether UDS code exists in the retail client. No hypothesis in
`docs/ARCHITECTURE_HYPOTHESES.md` is promoted to `Supported` by this rung.

## Next gate

The next authorized rung is **P0-C2 — Controlled HTTPS Visibility and Redirection-Path
Validation**, which requires its own explicit authorization. P0-C1 does not authorize
interception, CA installation, DNS redirection, client patching, or service implementation.
