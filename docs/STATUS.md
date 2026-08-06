# Status

## Project identity

- Project: Halo MCC Online Preservation
- Repository: `halo-mcc-online-preservation`
- Target: Halo: The Master Chief Collection, retail PC build
- Initial visibility: **private**
- Current phase: **P0 — Evidence bank and architecture adjudication**

## Accepted facts

**None.**

No claim currently satisfies `docs/EVIDENCE_POLICY.md` §"Claim format", which requires every
recorded claim to cite evidence IDs. No evidence IDs exist in this repository yet: P0-A is
repository bootstrap only and banks no retail, binary, or capture evidence.

Five entries previously listed here as accepted facts carried no evidence IDs and could not be
traced or re-adjudicated. They were relocated to `docs/ARCHITECTURE_HYPOTHESES.md` as H-008
through H-012, with their stated source context preserved. Nothing was deleted and no evidence
ID was manufactured to retain them.

A claim enters this section only when it cites at least one evidence ID recorded under
`evidence/` and its ledger state in `docs/ARCHITECTURE_HYPOTHESES.md` is `Supported`.

## Scope note: Halo Infinite

Halo Infinite is outside project scope. It may be used only as independent secondary source
(`docs/EVIDENCE_POLICY.md` class 4) for comparative research that suggests where to look. No
Infinite observation may be promoted to an MCC fact; each must be independently confirmed
against MCC retail evidence before it is accepted. Hypotheses below that name Infinite do so
as comparison only.

## Unresolved hypotheses

- The retail MCC client contains executable server-mode code equivalent to a UDS game payload.
- MCC exposes an endpoint-authority manifest comparable to Halo Infinite's settings document.
- MCC uses the same title-token flow or token version as Halo Infinite.
- MPSD is the authoritative MCC session directory for every target mode.
- A plain IP:port substitute is sufficient for all private-session transport.
- UDS allocation can be replaced cleanly with a self-hosted allocator.

## Current gate

P0 may complete only when:

1. Retail build identity is pinned and hashed. **Linux/Bazzite/Proton side banked and
   interactively confirmed** (`evidence/p0b1_bazzite_proton_build_bank/`,
   `evidence/p0b1a_interactive_launch/`; summarized in `docs/RETAIL_BUILD_BANK.md`). **Native
   Windows side (P0-B2) not yet banked** — this item is not complete until both platforms are.
2. Capture tooling is validated against visible ground-truth traffic. **Passive metadata capture
   built and exercised** (`evidence/p0c1_passive_connection_topology/`, tooling in
   `tools/capture/linux/`); the observed topology is summarized in
   `docs/CLIENT_BOOTSTRAP_TOPOLOGY.md`. **Decrypted-HTTPS visibility is still not validated**, and
   this item remains open: **P0-C2A** established that MCC honours an explicit proxy and mapped the
   governing certificate stores (`evidence/p0c2a_https_visibility/`), but **P0-C2B** then found MCC
   will **not complete Xbox Live sign-in through a proxy even with zero decryption**
   (`evidence/p0c2b_title_service_capture/`, `docs/TITLE_SERVICE_CAPTURE.md`). No MCC title-service
   exchange has been captured, and MCC certificate acceptance/pinning remains unresolved.
3. At least two controlled accounts and two Windows machines are available for session captures.
4. The endpoint/domain inventory is reproducible.
5. Tokens and personal identifiers are redacted from committed evidence.
6. ICE/STUN/UDP session-establishment evidence is documented.
7. The UDS-in-client hypothesis has a bounded binary-audit verdict.
8. An independent read-only model audit accepts the evidence ledger.

No Phase 1 shim or service implementation starts before this gate.
