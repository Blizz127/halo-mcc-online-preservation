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

## Rules

- `Supported` requires reproducible evidence.
- `Rejected` requires evidence contradicting the claim.
- `Partially supported` cannot authorize implementation beyond the proven portion.
- Absence of strings is not proof of absence.
- Captured behavior from Halo Infinite cannot be promoted to MCC fact without MCC evidence.
