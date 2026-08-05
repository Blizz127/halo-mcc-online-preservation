# Status

## Project identity

- Project: Halo MCC Online Preservation
- Repository: `halo-mcc-online-preservation`
- Target: Halo: The Master Chief Collection, retail PC build
- Initial visibility: **private**
- Current phase: **P0 — Evidence bank and architecture adjudication**

## Accepted facts

- MCC uses dedicated servers for matchmade games and Custom Game Browser sessions.
- Other MCC modes can use a peer-hosted session.
- The dedicated-server application is called the Unified Dedicated Server (UDS), a wrapper capable of configuring and launching server versions of MCC games.
- MCC client-to-UDS configuration uses an ICE/STUN-negotiated UDP path.
- MCC officially supports launching on PC with Easy Anti-Cheat disabled for mods and limited online services.

## Unresolved hypotheses

- The retail MCC client contains executable server-mode code equivalent to a UDS game payload.
- MCC exposes an endpoint-authority manifest comparable to Halo Infinite's settings document.
- MCC uses the same title-token flow or token version as Halo Infinite.
- MPSD is the authoritative MCC session directory for every target mode.
- A plain IP:port substitute is sufficient for all private-session transport.
- UDS allocation can be replaced cleanly with a self-hosted allocator.

## Current gate

P0 may complete only when:

1. Retail build identity is pinned and hashed.
2. Capture tooling is validated against visible ground-truth traffic.
3. At least two controlled accounts and two Windows machines are available for session captures.
4. The endpoint/domain inventory is reproducible.
5. Tokens and personal identifiers are redacted from committed evidence.
6. ICE/STUN/UDP session-establishment evidence is documented.
7. The UDS-in-client hypothesis has a bounded binary-audit verdict.
8. An independent read-only model audit accepts the evidence ledger.

No Phase 1 shim or service implementation starts before this gate.
