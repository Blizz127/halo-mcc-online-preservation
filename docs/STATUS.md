# Status

## Project identity

- Project: Halo MCC Online Preservation
- Repository: `halo-mcc-online-preservation`
- Target: Halo: The Master Chief Collection, retail PC build
- Initial visibility: **private**
- Current phase: **P0 — Evidence bank and architecture adjudication**

## Accepted facts

**No architecture hypothesis has yet been promoted to an accepted fact.**

Evidence IDs do exist in this repository. P0-B1 through P0-C2C banked retail-build, launch,
passive-topology, HTTPS-visibility, title-service-capture, and post-authentication-interception
evidence under `evidence/`; their reader-facing summaries cite those IDs. P0-C2D0 and P0-C2D0-R2
additionally bank synthetic tooling-validation evidence. None of that evidence, by itself, completes
the promotion requirements for an architecture hypothesis.

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
   governing certificate stores (`evidence/p0c2a_https_visibility/`), but in **P0-C2B** both tested
   explicit-proxy configurations **coincided with Xbox sign-in failure despite successful blind
   tunneling** (`evidence/p0c2b_title_service_capture/`, `docs/TITLE_SERVICE_CAPTURE.md`). **P0-C2C** then
   confirmed identity signs in normally with no proxy, but a post-boot single-host redirect did not
   intercept the settings service because MCC reuses a boot-time connection
   (`evidence/p0c2c_post_auth_interception/`, `docs/POST_AUTH_INTERCEPTION.md`). No MCC title-service
   exchange has been captured, and MCC certificate acceptance/pinning remains unresolved.
   Codex Sol returned `C. REJECT — RELAY SAFETY FAILURE` for the first local **P0-C2D0 pre-launch
   interception tooling** candidate; **P0-C2D0-R1 corrected every reported blocker using synthetic
   tests, and P0-C2D0-R2 corrected the live-preflight contract**
   (`evidence/p0c2d0_prelaunch_tooling/`, `evidence/p0c2d0r2_live_preflight_correction/`,
   `docs/PRELAUNCH_INTERCEPTION.md`). **P0-C2D then passed the authorized live single-host blind-
   relay rung** (`A. BLIND RELAY PASS`): cached Microsoft/Xbox identity succeeded, MCC contacted
   `settings.svc.halowaypoint.com` through `127.0.0.77:443`, exchanged 4,728 client-to-upstream and
   29,226 upstream-to-client encrypted bytes, and reached the main menu without a certificate or
   service error (`E-P0C2D-001` through `E-P0C2D-005`,
   `evidence/p0c2d_live_blind_relay/`). Exact rollback completed before the relay deadline and a
   separate normal post-rollback launch succeeded. This proves opaque transport only; no TLS was
   terminated and no request, response, settings authority, CA acceptance, or pinning verdict was
   observed. **P0-C2E manifest discovery remains not started**.
3. At least two controlled accounts and two Windows machines are available for session captures.
4. The endpoint/domain inventory is reproducible.
5. Tokens and personal identifiers are redacted from committed evidence.
6. ICE/STUN/UDP session-establishment evidence is documented.
7. The UDS-in-client hypothesis has a bounded binary-audit verdict.
8. An independent read-only model audit accepts the evidence ledger.

No Phase 1 shim or service implementation starts before this gate.
