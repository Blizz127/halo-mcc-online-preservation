# P0-C1 unresolved endpoints

Endpoints this rung could **not** classify to the standard required by `docs/EVIDENCE_POLICY.md`.
They are recorded here rather than assigned a plausible-sounding label, and each is left for a
later rung to adjudicate.

## 1. Target-process sockets with no DNS-resolved peer name

29 sockets were owned by an MCC/Proton/Steam process but their peer address never
appeared as an answer in any DNS transaction observed during the capture. Causes cannot be
distinguished from this evidence alone: the name may have been resolved before monitoring began
and served from cache, resolved by a resolver path the monitor does not observe, or the peer may
have been reached by a literal address with no lookup at all.

| Proto | Peer address | Port | Role(s) | Samples |
|---|---|---:|---|---:|
| tcp | `127.0.0.1` | 45429 | steam_client | 1800 |
| tcp | `127.0.0.1` | 42590 | steam_client | 1800 |
| tcp | `127.0.0.1` | 57343 | steam_client | 1800 |
| tcp | `<PRIVATE_HOST_1>` | 8009 | steam_client | 1800 |
| tcp | `162.254.194.56` | 27018 | steam_client | 1800 |
| tcp | `127.0.0.1` | 43966 | steam_client | 1800 |
| tcp | `<PRIVATE_HOST_2>` | 8009 | steam_client | 1800 |
| tcp | `127.0.0.1` | 39895 | steam_client | 1800 |
| tcp | `<PRIVATE_HOST_3>` | 56700 | steam_client | 1800 |
| tcp | `127.0.0.1` | 51088 | steam_client | 1800 |
| tcp | `<PRIVATE_HOST_4>` | 8009 | steam_client | 1800 |
| tcp | `<PRIVATE_HOST_5>` | 27036 | steam_client | 1800 |
| tcp | `184.29.31.209` | 443 | steam_client | 1027 |
| tcp | `127.0.0.1` | 55020 | steam_client | 859 |
| tcp | `127.0.0.1` | 45608 | steam_client | 855 |
| tcp | `::1` | 631 | mcc_game | 852 |
| tcp | `127.0.0.1` | 58864 | steam_client | 796 |
| tcp | `127.0.0.1` | 58860 | steam_client | 796 |
| tcp | `199.46.35.121` | 443 | proton_wine | 789 |
| tcp | `20.184.175.4` | 443 | proton_wine | 789 |
| tcp | `150.171.110.2` | 443 | proton_wine | 60 |

## 2. STUN-port traffic not attributable to MCC

586 UDP packets to ports 3478/3479 were present in the capture. Of these, **32 packets to 5
addresses are attributable to MCC**, because those addresses were resolved from Halo-operated
COTURN hostnames during the session (see `REPORT.md`).

The remaining ~554 packets went to addresses with **no DNS name observed and no process owner in
`ss`**. Those address ranges belong to this host's VPN relay infrastructure, which independently
uses STUN. That is contextual reasoning about address ownership, which
`docs/EVIDENCE_POLICY.md` permits only as supporting context and never as proof of application
purpose — so this traffic is recorded as **not attributable to MCC**, not as "MCC does not use
STUN" and not as "the VPN did it".

## 3. Sockets with no process owner at all

39 observed sockets carried no owner in `ss` output
(kernel-owned services such as DHCP and NTP, and sockets belonging to other users). No attempt
was made to infer their purpose.

## 4. What this rung deliberately did not determine

Per the P0-C1 interpretation boundary, none of the following is established here and none should
be inferred from the tables above: plaintext API schemas, token formats, whether server-side
validation can be bypassed, whether a local replacement service would be accepted, whether DNS
redirection is sufficient, whether TLS certificate validation can be altered, whether native
Windows behaves identically, or whether UDS code exists in the retail client.
