# P0-C1 process-to-socket map

Socket ownership as reported by `ss -tunpH`, with roles resolved from process **argv** rather
than `comm`.

## Why argv, not `comm`

`ss` reports the kernel's `comm` value, which is the name of the process's *main thread*.
`MCC-Win64-Shipping.exe` renames its main thread to `MAIN_THREAD` shortly after startup, so once
the game is running its sockets appear under a generic name that matches no game pattern.
Attribution keyed on `comm` alone therefore silently discards the game's own traffic — exactly
the traffic this rung exists to record. Roles below are resolved by PID against an argv-derived
map, with `comm` used only as a fallback.

Wrapper processes each carry the launched executable's path in their own argv, so a naive argv
substring test would label the whole Steam→Proton→game chain as the game. Wrapper markers are
matched first and classified as `proton_wine`.

## Observed ownership

### `mcc_game` — MCC game process (`MCC-Win64-Shipping.exe`, comm `MAIN_THREAD`)

97 socket observations, 94 with a DNS-resolved peer name.

| Proto | Peer port | Peer name(s) | Samples |
|---|---:|---|---:|
| tcp | 443 | `api.epicgames.dev`, `api.epicgames.dev.cdn.cloudflare.net` | 824 |
| tcp | 443 | `rta.xboxlive.com`, `rta.xboxlive.com.akadns.net` | 806 |
| tcp | 443 | `notification.svc.halowaypoint.com`, `s3p-notification-eus-dispatcher-production.eastus.cloudapp.azure.com` | 805 |
| tcp | 443 | `s3p-ingestion-1-eus2-dispatcher-production.eastus2.cloudapp.azure.com`, `telemetry.svc.halowaypoint.com` | 804 |
| tcp | 443 | `userpresence.xboxlive.com`, `userpresence.xboxlive.com.akadns.net` | 599 |
| tcp | 443 | `onedscolprdgwc02.germanywestcentral.cloudapp.azure.com`, `vortex.data.microsoft.com` | 555 |
| tcp | 443 | `onedscolprdcus52.centralus.cloudapp.azure.com`, `vortex.data.microsoft.com` | 231 |
| tcp | 443 | `title.mgt.xboxlive.com`, `title.mgt.xboxlive.com.akadns.net` | 101 |
| tcp | 443 | `ee38.playfabapi.com`, `mcc-production.azurefd.net`, `mr-azurefd.tm-azurefd.net` | 101 |
| tcp | 443 | `EE38.playfabapi.com`, `ee38.playfabapi.com`, `mcc-production.azurefd.net` | 99 |
| tcp | 443 | `onedscolprdaus51.australiasoutheast.cloudapp.azure.com`, `vortex.data.microsoft.com` | 81 |
| tcp | 443 | `userstats.xboxlive.com`, `userstats.xboxlive.com.akadns.net` | 71 |
| tcp | 443 | `achievements.xboxlive.com`, `achievements.xboxlive.com.akadns.net` | 71 |
| tcp | 443 | `peoplehub.xboxlive.com`, `user-att-107-135-96-0.e87.b.akamaiedge.net` | 71 |
| tcp | 443 | `sessiondirectory.xboxlive.com`, `sessiondirectory.xboxlive.com.akadns.net` | 71 |
| tcp | 443 | `s3p-settings-wus-dispatcher-production.westus.cloudapp.azure.com`, `settings.svc.halowaypoint.com` | 71 |
| tcp | 443 | `gamecms-hacs.svc.halowaypoint.com`, `user-att-107-135-96-0.a925.dscr.akamai.net` | 70 |
| tcp | 443 | `halostats.svc.halowaypoint.com`, `s3p-halostats-dispatcher-production.eastus2.cloudapp.azure.com` | 70 |
| tcp | 443 | `entitlements.svc.halowaypoint.com`, `s3l-entitlements-eus-dispatcher-production.eastus.cloudapp.azure.com` | 70 |
| tcp | 443 | `banprocessor.svc.halowaypoint.com`, `s3p-banprocessor-eus2-dispatcher-production.eastus2.cloudapp.azure.com` | 70 |
| tcp | 443 | `profile.xboxlive.com`, `profile.xboxlive.com.akadns.net` | 70 |
| tcp | 443 | `WestUs.tts.speech.microsoft.com`, `istio-ingress-speech2-ame10-usw.westus.cloudapp.azure.com` | 66 |
| tcp | 443 | `login.live.com`, `www.tm.v4.a.prd.aadg.akadns.net` | 63 |
| tcp | 443 | `xsts.auth.xboxlive.com`, `xsts.auth.xboxlive.com.akadns.net` | 62 |
| tcp | 443 | `notify.xboxlive.com`, `notify.xboxlive.com.akadns.net` | 61 |

### `mcc_launcher` — MCC launcher (`mcclauncher.exe`)

3 socket observations, 1 with a DNS-resolved peer name.

| Proto | Peer port | Peer name(s) | Samples |
|---|---:|---|---:|
| tcp | 443 | `modules-cdn.eac-prod.on.epicgames.com` | 4 |

### `proton_wine` — Proton / Wine layer (`wineserver`, `winedevice.exe`, `xalia.exe`, `steam.exe` shim, pressure-vessel)

144 socket observations, 137 with a DNS-resolved peer name.

| Proto | Peer port | Peer name(s) | Samples |
|---|---:|---|---:|
| tcp | 443 | `api.epicgames.dev`, `api.epicgames.dev.cdn.cloudflare.net` | 824 |
| tcp | 443 | `rta.xboxlive.com`, `rta.xboxlive.com.akadns.net` | 806 |
| tcp | 443 | `notification.svc.halowaypoint.com`, `s3p-notification-eus-dispatcher-production.eastus.cloudapp.azure.com` | 805 |
| tcp | 443 | `s3p-ingestion-1-eus2-dispatcher-production.eastus2.cloudapp.azure.com`, `telemetry.svc.halowaypoint.com` | 804 |
| tcp | 443 | `userpresence.xboxlive.com`, `userpresence.xboxlive.com.akadns.net` | 599 |
| tcp | 443 | `onedscolprdgwc02.germanywestcentral.cloudapp.azure.com`, `vortex.data.microsoft.com` | 555 |
| tcp | 443 | `userstats.xboxlive.com`, `userstats.xboxlive.com.akadns.net` | 245 |
| tcp | 443 | `onedscolprdcus52.centralus.cloudapp.azure.com`, `vortex.data.microsoft.com` | 231 |
| tcp | 443 | `sessiondirectory.xboxlive.com`, `sessiondirectory.xboxlive.com.akadns.net` | 165 |
| tcp | 443 | `EE38.playfabapi.com`, `ee38.playfabapi.com`, `mcc-production.azurefd.net` | 150 |
| tcp | 443 | `profile.xboxlive.com`, `profile.xboxlive.com.akadns.net` | 102 |
| tcp | 443 | `title.mgt.xboxlive.com`, `title.mgt.xboxlive.com.akadns.net` | 101 |
| tcp | 443 | `ee38.playfabapi.com`, `mcc-production.azurefd.net`, `mr-azurefd.tm-azurefd.net` | 101 |
| tcp | 443 | `onedscolprdaus51.australiasoutheast.cloudapp.azure.com`, `vortex.data.microsoft.com` | 81 |
| tcp | 443 | `mcc-production.azurefd.net`, `mr-azurefd.tm-azurefd.net` | 76 |
| tcp | 443 | `achievements.xboxlive.com`, `achievements.xboxlive.com.akadns.net` | 71 |
| tcp | 443 | `peoplehub.xboxlive.com`, `user-att-107-135-96-0.e87.b.akamaiedge.net` | 71 |
| tcp | 443 | `s3p-settings-wus-dispatcher-production.westus.cloudapp.azure.com`, `settings.svc.halowaypoint.com` | 71 |
| tcp | 443 | `gamecms-hacs.svc.halowaypoint.com`, `user-att-107-135-96-0.a925.dscr.akamai.net` | 70 |
| tcp | 443 | `halostats.svc.halowaypoint.com`, `s3p-halostats-dispatcher-production.eastus2.cloudapp.azure.com` | 70 |
| tcp | 443 | `entitlements.svc.halowaypoint.com`, `s3l-entitlements-eus-dispatcher-production.eastus.cloudapp.azure.com` | 70 |
| tcp | 443 | `banprocessor.svc.halowaypoint.com`, `s3p-banprocessor-eus2-dispatcher-production.eastus2.cloudapp.azure.com` | 70 |
| tcp | 443 | `WestUs.tts.speech.microsoft.com`, `istio-ingress-speech2-ame10-usw.westus.cloudapp.azure.com` | 66 |
| tcp | 443 | `s3p-settings-eus-dispatcher-production.eastus.cloudapp.azure.com`, `settings.svc.halowaypoint.com` | 63 |
| tcp | 443 | `login.live.com`, `www.tm.v4.a.prd.aadg.akadns.net` | 63 |
| tcp | 443 | `leaderboards.xboxlive.com`, `leaderboards.xboxlive.com.akadns.net` | 62 |
| tcp | 443 | `xsts.auth.xboxlive.com`, `xsts.auth.xboxlive.com.akadns.net` | 62 |
| tcp | 443 | `notify.xboxlive.com`, `notify.xboxlive.com.akadns.net` | 61 |
| tcp | 443 | `modules-cdn.eac-prod.on.epicgames.com` | 4 |

### `steam_client` — Steam client (`steam`, `steamwebhelper`, `gameoverlayui`)

23 socket observations, 4 with a DNS-resolved peer name.

| Proto | Peer port | Peer name(s) | Samples |
|---|---:|---|---:|
| tcp | 443 | `shared.steamstatic.com`, `shared.valve.map.fastly.net` | 520 |
| tcp | 443 | `api.steampowered.com` | 76 |
| tcp | 443 | `blob.avc09prdstrz05a.trafficmanager.net`, `steamclouduseast2.blob.core.windows.net` | 61 |

## Unattributed sockets

39 observed sockets carried no process owner in `ss`
output. `ss` reports owners only for processes the invoking user can see; kernel-owned sockets
(DHCP, NTP) and sockets belonging to other users appear without attribution. These are recorded
as unresolved rather than guessed at — see `unresolved_endpoints.md`.
