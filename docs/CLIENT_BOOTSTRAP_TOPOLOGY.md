# Client bootstrap topology

Observed connection topology for the retail MCC client on Bazzite/Steam/Proton. Every statement
here cites an evidence ID resolving to `evidence/p0c1_passive_connection_topology/`. This document
summarizes; that directory is authoritative, and if the two disagree the evidence wins.

**Platform scope.** Everything below is Linux/Proton only. Native Windows behavior is unobserved
(P0-B2 remains unstarted) and must not be assumed identical.

**Evidence class.** All of this is *retail observation* of connection metadata
(`docs/EVIDENCE_POLICY.md` class 2). No payload was decrypted or inspected, so nothing here
describes an API, a schema, or a token.

## Service layers observed

| Layer | Representative endpoints | Evidence |
|---|---|---|
| Steam / storefront | `api.steampowered.com`, `cmp1-dfw2.steamserver.net`, `p2p-dfw2.discovery.steamserver.net` | `E-P0C1-001` |
| Microsoft identity | `login.live.com` | `E-P0C1-003` |
| Xbox token exchange | `xsts.auth.xboxlive.com` | `E-P0C1-003` |
| Xbox platform | `sessiondirectory.xboxlive.com` (MPSD), `rta.xboxlive.com`, `notify.xboxlive.com`, `userpresence`, `userstats`, `leaderboards`, `achievements`, `profile`, `peoplehub`, `title.mgt` | `E-P0C1-005`, `E-P0C1-002` |
| MCC / Halo title services | `settings`, `entitlements`, `halostats`, `banprocessor`, `notification`, `telemetry`, `gamecms-hacs` — all `*.svc.halowaypoint.com`; plus `mcc-production.azurefd.net` | `E-P0C1-001` |
| Multiplayer QoS | `mpsqosprod.<region>.cloudapp.azure.com`, 15 Azure regions, UDP/3075 | `E-P0C1-006` |
| TURN relays | `COTURN.HW-USW*-PROD.halowaypoint.com`, `turn-mcc*.trafficmanager.net`, UDP/3478 | `E-P0C1-007` |
| Anti-cheat delivery | `modules-cdn.eac-prod.on.epicgames.com`, `api.epicgames.dev` | `E-P0C1-008` |
| Telemetry / CDN | `vortex.data.microsoft.com`, Akamai edge names | `E-P0C1-001` |

Backend decomposition is visible through CNAME chains: each `*.svc.halowaypoint.com` name
resolves to a named Azure dispatcher such as
`s3p-settings-eus-dispatcher-production.eastus.cloudapp.azure.com`. That is infrastructure
naming, not documented architecture.

## Bootstrap order (clean cold launch, C2b)

Offsets are first DNS resolution relative to launch (`E-P0C1-003`):

```
+41.7s   anti-cheat module CDN        (mcc_launcher)
+51.7s   Xbox title management
+70.7s   Microsoft identity           login.live.com
+70.9s   Xbox token exchange          xsts.auth.xboxlive.com
+71.4s   Xbox platform services       rta, notify, achievements, peoplehub
+72.2s   Halo title services          gamecms, halostats, notification, telemetry
+73.1s   TURN relay endpoints         COTURN.*.halowaypoint.com
+87.2s   entitlements, ban processing
```

No Halo title service resolved before identity. This is **ordering of resolution**, not proven
causal dependency.

## Transport findings

- **TCP/443 dominates** every confirmed service layer.
- **UDP is present during menu-only activity**, contrary to what socket sampling alone suggested:
  QoS probes on **UDP/3075** to 15 Azure regions (`E-P0C1-006`) and **UDP/3478** to Halo-operated
  TURN relays (`E-P0C1-007`). Both are short-lived enough to be invisible to 0.5s `ss` sampling
  and were recovered only from the packet record.
- **No gameplay session transport was observed**, because no match was started.

## What this does not establish

Reading further than the evidence supports is the main risk with this document:

- **Not** an API, schema, or token format — no payload was decrypted.
- **Not** MPSD's authority. `sessiondirectory.xboxlive.com` was *contacted* by the game process;
  whether it is authoritative for any MCC mode is untested (H-004 stays `Unproven`).
- **Not** ICE negotiation or a peer transport path. TURN relays were resolved and probed; no
  candidate exchange or session was observed (H-005, H-011 stay `Unproven`).
- **Not** dedicated-server allocation. Region QoS probing is consistent with regional selection,
  but no allocation or assignment was seen (H-008 stays `Unproven`).
- **Not** anti-cheat state. Module delivery was observed; `evidence/p0b1a_interactive_launch/`
  separately recorded no EAC process or module at its checkpoints. Both facts stand; neither
  resolves the other (H-012 unchanged).
- **Not** native Windows behavior, and **not** whether any of this can be redirected, replaced, or
  intercepted — that is P0-C2's question and is unanswered here.

## Reproducing

```bash
# one bounded, privileged capture (operator-run; payloads truncated at capture time)
sudo bash tools/capture/linux/run_capture.sh <scratch-dir-outside-repo>

# unprivileged collectors, run continuously and sliced by timestamp markers
python3 tools/capture/linux/dns_monitor.py run <scratch>/dns.log --seconds N
python3 tools/capture/linux/socket_poller.py <scratch>/flows.jsonl --seconds N --interval 0.5

# join, classify, and emit sanitized inventories
python3 tools/capture/linux/build_topology.py <index.json> <scratch> <outdir> --pcap <scratch>/p0c1_full.pcap
```

See `tools/capture/linux/README.md` for the redaction policy, the privacy filter, and why a
`Confirmed` classification requires process attribution *and* a suffix match rather than a
hostname alone.
