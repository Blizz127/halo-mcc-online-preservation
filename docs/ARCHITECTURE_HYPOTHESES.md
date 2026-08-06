# Architecture hypotheses ledger

Every material claim must be tracked here before it becomes architecture.

| ID | Claim | State | Required evidence | Consequence |
|---|---|---|---|---|
| H-001 | MCC retail contains reachable server-mode game code | Unproven | Static references plus dynamic launch/reachability evidence | Determines whether self-hosted UDS-like servers are feasible |
| H-002 | MCC has a machine-readable settings/authority manifest | Unproven | Captured request/response or binary constant with successful fetch | Could turn endpoint discovery into deterministic inventory |
| H-003 | MCC uses an earlier Spartan-token variant | Unproven | Retail request headers, token endpoint payload, and response schema | Determines local authentication compatibility surface |
| H-004 | MPSD is used for target MCC sessions | Unproven | Xbox service calls and session documents tied to a controlled lifecycle | Determines whether a compatible session-directory service is needed |
| H-005 | Plain routable endpoints can replace platform secure addresses | Unproven | Two-client capture and controlled substitution test | Determines transport implementation scale |
| H-006 | MCC dedicated allocation can fall back to peer host | Partially supported | Official incident behavior plus reproducible retail observation | Provides a bounded fallback if UDS is unavailable |
| H-007 | Proxy-based TLS capture is sufficient | **Narrowed — no path yet observes a title-service exchange** (P0-C2B, P0-C2C) | Wireshark-visible request also appears decrypted in proxy capture | Determines whether transparent interception is needed |
| H-008 | MCC uses dedicated servers for matchmade games and Custom Game Browser sessions | Unproven | Retail capture of one matchmade and one CGB session showing server allocation and the resulting connection | Determines which modes require a server-side host substitute |
| H-009 | MCC modes outside matchmaking and CGB can run on a peer-hosted session | Unproven | Retail capture of a custom game or campaign co-op showing a client acting as host | Bounds how much of the target surface can avoid dedicated hosting; overlaps H-006 |
| H-010 | The MCC dedicated-server application is a "Unified Dedicated Server" (UDS) — a wrapper that configures and launches server builds of MCC games | Unproven | Cited official primary source, or binary/retail observation of the wrapper and its launch contract | Defines what any self-hosted server would have to match; prerequisite framing for H-001 |
| H-011 | MCC client-to-UDS configuration uses an ICE/STUN-negotiated UDP path | Unproven | Two-client capture showing STUN/ICE candidate exchange preceding UDS configuration | Determines transport implementation scale; narrower restatement of H-005 |
| H-012 | MCC officially supports launching on PC with Easy Anti-Cheat disabled, for mods and a limited subset of online services | Unproven | Cited official support or vendor documentation banked with an evidence ID, plus retail confirmation of the launch mode | Determines the lawful, sanctioned launch mode for all testing |

## P0-C1 passive-topology evidence (no state changes)

`evidence/p0c1_passive_connection_topology/` banked connection-metadata evidence touching several
hypotheses. **No hypothesis state changed**, because passive metadata shows *that* an endpoint was
contacted, never *what it does* — and every hypothesis below turns on behavior, authority, or
format that TLS made unobservable. The observations are recorded here so a later rung does not
have to rediscover them, and so nobody mistakes "endpoint exists" for "hypothesis supported".

| ID | Relevant P0-C1 observation | Why the state does not change |
|---|---|---|
| H-002 | `settings.svc.halowaypoint.com` exists, is contacted by the game process at launch, and resolves to a named settings dispatcher (`E-P0C1-001`) | A suggestive name is not a manifest. No response was observed, so whether it is machine-readable or authoritative is untested |
| H-003 | `xsts.auth.xboxlive.com` is contacted ~0.2s after `login.live.com` (`E-P0C1-003`) | Ordering only. No token, header, or payload was observed; the token *format* question is untouched |
| H-004 | `sessiondirectory.xboxlive.com` (MPSD) is contacted by the MCC game process during menu-only activity (`E-P0C1-005`) | Contact is not authority. Whether MPSD is authoritative *for every target mode* needs session-lifecycle evidence this rung did not gather |
| H-005 / H-011 | Halo-operated TURN relays (`COTURN.*.halowaypoint.com`, `turn-mcc*.trafficmanager.net`) resolved and probed on UDP/3478 (`E-P0C1-007`) | Relay endpoints existing and receiving 32 packets is a *necessary condition* for an ICE/TURN path, not a demonstration of one. No candidate exchange or session was observed |
| H-008 | QoS probing on UDP/3075 across 15 Azure regions during launch and menus (`E-P0C1-006`) | Consistent with regional server selection, but no allocation, assignment, or match was observed. Attribution here is by destination address, not process ownership |
| H-012 | Anti-cheat module CDN contacted by the launcher (`E-P0C1-008`), while `E-P0B1A-004` recorded no EAC process or module | Both facts stand; neither resolves the other. Module delivery is not proof of enforcement |

## P0-C2B / P0-C2C narrowing of H-007

**H-007 is narrowed, not rejected. No path tried so far observes an MCC title-service exchange.**

*P0-C2B (boot-time proxy).* In both tested explicit-proxy configurations, MCC's Microsoft/Xbox
sign-in failed while nothing was decrypted — every identity host blind-tunnelled, zero TLS
terminations (`E-P0C2A-004`, `E-P0C2B-001`). Not attributable to relay failure: the tunnels carried
6–63 KB per host bidirectionally, and fixing the most plausible mechanical cause (tunnel half-close
teardown) did not change the outcome (`E-P0C2B-002`). This does **not** prove every possible proxy
method fails during sign-in; the cause is unresolved by choice (diagnosing it means decrypting
forbidden identity traffic), and the failure is transient (sign-in works normally after rollback).

*P0-C2C (post-boot redirect).* Signing in directly and then redirecting exactly one settings host
after the main menu also did **not** yield an exchange: MCC reused a persistent connection to the
settings service opened at boot, never re-resolved, and never contacted the observer (`E-P0C2C-003`).

Consequence for later rungs: neither a boot-time proxy (breaks sign-in) nor a post-boot name
redirect (misses reused connections) has produced a decrypted title-service request. A working path
must either force a genuinely fresh settings fetch on a new connection, or act before the connection
is established without running identity under interception — and, for certificate-trust evidence,
have the CA present before that connection (`E-P0C2C-004`).

## Provenance of H-008 through H-012

H-008 through H-012 were previously recorded in `docs/STATUS.md` as **accepted facts**. None
cited an evidence ID, so none satisfied `docs/EVIDENCE_POLICY.md` §"Claim format" and none
could be traced or re-adjudicated. They were moved here rather than deleted, and no evidence
ID was invented to keep them.

Their source context, as far as it can be reconstructed, is worth preserving as investigation
leads: H-008, H-009, H-010, and H-011 read as paraphrases of public statements about MCC's
online architecture, and H-012 reads as a paraphrase of official MCC support documentation for
the EAC-disabled launch mode. That context indicates where to look for primary sources; it is
not itself evidence. Each becomes `Supported` only under the normal rules below — a cited,
reproducible source banked under `evidence/`.

## Scope of Halo Infinite material

Halo Infinite is outside project scope. It is admissible only as an independent secondary
source (`docs/EVIDENCE_POLICY.md` class 4): it may direct where to look and what shape to
expect, and nothing more. Any Infinite-derived expectation must be independently confirmed
against MCC retail, binary, or capture evidence before it changes a claim's state here.
H-002 and H-003 name Infinite for comparison only.

## Rules

- `Supported` requires reproducible evidence.
- `Rejected` requires evidence contradicting the claim.
- `Partially supported` cannot authorize implementation beyond the proven portion.
- Absence of strings is not proof of absence.
- Captured behavior from Halo Infinite cannot be promoted to MCC fact without MCC evidence.
