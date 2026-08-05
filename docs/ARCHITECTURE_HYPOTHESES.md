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
| H-007 | Proxy-based TLS capture is sufficient | Unproven for MCC | Wireshark-visible request also appears decrypted in proxy capture | Determines whether transparent interception is needed |
| H-008 | MCC uses dedicated servers for matchmade games and Custom Game Browser sessions | Unproven | Retail capture of one matchmade and one CGB session showing server allocation and the resulting connection | Determines which modes require a server-side host substitute |
| H-009 | MCC modes outside matchmaking and CGB can run on a peer-hosted session | Unproven | Retail capture of a custom game or campaign co-op showing a client acting as host | Bounds how much of the target surface can avoid dedicated hosting; overlaps H-006 |
| H-010 | The MCC dedicated-server application is a "Unified Dedicated Server" (UDS) — a wrapper that configures and launches server builds of MCC games | Unproven | Cited official primary source, or binary/retail observation of the wrapper and its launch contract | Defines what any self-hosted server would have to match; prerequisite framing for H-001 |
| H-011 | MCC client-to-UDS configuration uses an ICE/STUN-negotiated UDP path | Unproven | Two-client capture showing STUN/ICE candidate exchange preceding UDS configuration | Determines transport implementation scale; narrower restatement of H-005 |
| H-012 | MCC officially supports launching on PC with Easy Anti-Cheat disabled, for mods and a limited subset of online services | Unproven | Cited official support or vendor documentation banked with an evidence ID, plus retail confirmation of the launch mode | Determines the lawful, sanctioned launch mode for all testing |

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
