# P0-C1 connection timeline

Chronology of **first DNS resolution** for each MCC-relevant hostname, relative to the start of
the clean cold launch (scenario **C2b**, offset `0.0`). Only hostnames matching a known service
family are listed; unrelated host traffic is excluded by the privacy filter described in
`REPORT.md`.

Two caveats apply to reading this as a strict causal order:

1. **DNS caching.** A name resolved in an earlier scenario may not be re-resolved during C2b, so a
   negative offset means "first seen earlier in the session", not "not used at launch".
2. **Resolution is not contact.** A name appearing here was looked up; whether the client actually
   connected is recorded separately in `flow_inventory.csv` and, for short-lived UDP, in
   `REPORT.md`. At least one family here was resolved and probed only over UDP that socket
   sampling never saw.

| Offset (s) | Scenario | Hostname | Classification |
|---:|---|---|---|
| -388.0 | earlier | `api.epicgames.dev` | Likely classification requiring verification |
| -364.3 | C5 | `p2p-dfw2.discovery.steamserver.net` | Confirmed Steam |
| -253.7 | C5 | `mcc-production.azurefd.net` | Confirmed MCC/Halo title service |
| -252.9 | C5 | `sessiondirectory.xboxlive.com` | Confirmed Xbox platform |
| -252.9 | C5 | `ee38.playfabapi.com` | Likely classification requiring verification |
| -252.8 | C5 | `userstats.xboxlive.com` | Confirmed Xbox platform |
| -246.4 | C5 | `profile.xboxlive.com` | Confirmed Xbox platform |
| -236.6 | C5 | `EE38.playfabapi.com` | Likely classification requiring verification |
| -206.4 | C5 | `leaderboards.xboxlive.com` | Confirmed Xbox platform |
| -195.3 | C5 | `userpresence.xboxlive.com` | Confirmed Xbox platform |
| -91.7 | C6 | `settings.svc.halowaypoint.com` | Confirmed MCC/Halo title service |
| -28.9 | C6 | `api.steampowered.com` | Confirmed Steam |
| +41.7 | C2b | `modules-cdn.eac-prod.on.epicgames.com` | Likely classification requiring verification |
| +51.7 | C2b | `title.mgt.xboxlive.com` | Confirmed Xbox platform |
| +70.7 | C2b | `login.live.com` | Confirmed Microsoft identity |
| +70.9 | C2b | `xsts.auth.xboxlive.com` | Confirmed Xbox platform |
| +71.4 | C2b | `rta.xboxlive.com` | Confirmed Xbox platform |
| +71.4 | C2b | `notify.xboxlive.com` | Confirmed Xbox platform |
| +71.6 | C2b | `achievements.xboxlive.com` | Confirmed Xbox platform |
| +71.6 | C2b | `peoplehub.xboxlive.com` | Confirmed Xbox platform |
| +71.8 | C2b | `vortex.data.microsoft.com` | CDN/telemetry |
| +72.2 | C2b | `gamecms-hacs.svc.halowaypoint.com` | Confirmed MCC/Halo title service |
| +72.2 | C2b | `halostats.svc.halowaypoint.com` | Confirmed MCC/Halo title service |
| +72.3 | C2b | `notification.svc.halowaypoint.com` | Confirmed MCC/Halo title service |
| +72.5 | C2b | `telemetry.svc.halowaypoint.com` | Confirmed MCC/Halo title service |
| +73.1 | C2b | `COTURN.HW-USW-PROD.halowaypoint.com` | Confirmed MCC/Halo title service |
| +73.1 | C2b | `COTURN.HW-USW01-PROD.halowaypoint.com` | Confirmed MCC/Halo title service |
| +73.1 | C2b | `turn-mcc01.trafficmanager.net` | CDN/telemetry |
| +73.1 | C2b | `turn-mcc.trafficmanager.net` | CDN/telemetry |
| +87.2 | C2b | `banprocessor.svc.halowaypoint.com` | Confirmed MCC/Halo title service |
| +87.3 | C2b | `entitlements.svc.halowaypoint.com` | Confirmed MCC/Halo title service |
| +214.8 | earlier | `shared.steamstatic.com` | Confirmed Steam |
| +214.8 | earlier | `shared.valve.map.fastly.net` | CDN/telemetry |
| +267.2 | earlier | `twimg.twitter.map.fastly.net` | CDN/telemetry |

## Cold-launch order (C2b only)

Reading only the positive offsets — the clean cold launch with collectors already running — the
client's bootstrap order was:

1. **Anti-cheat module delivery** (`modules-cdn.eac-prod.on.epicgames.com`, +41.7s)
2. **Xbox title management** (`title.mgt.xboxlive.com`, +51.7s)
3. **Microsoft identity** (`login.live.com`, +70.7s)
4. **Xbox security-token exchange** (`xsts.auth.xboxlive.com`, +70.9s)
5. **Xbox platform services** — real-time activity, notification, achievements, people (+71.4s to +71.6s)
6. **Halo title services** — game CMS, stats, notification, telemetry (+72.2s to +72.5s)
7. **TURN relay endpoints** (`COTURN.*.halowaypoint.com`, `turn-mcc*.trafficmanager.net`, +73.1s)
8. **Entitlement and ban processing** (+87.2s to +87.3s)

Identity precedes every Halo-specific service, and the token exchange (`xsts.auth`) is resolved
within ~0.2s of the identity endpoint. No Halo title service is resolved before identity.
