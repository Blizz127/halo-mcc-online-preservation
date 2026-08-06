# Roadmap

## P0 — Bank and adjudicate

### P0-A: Repository and evidence policy
Create the private repository, pin scope, establish secret handling, and add evidence templates.

### P0-B: Retail build bank
Record storefront, app/build identifiers, Steam depot manifests where lawfully available, file hashes, installed DLC/title packages, launch modes, and tool versions. Do not commit retail files.

### P0-C: Capture-path validation
Run Wireshark as ground truth. Test Fiddler/mitmproxy with WinHTTP proxy configuration. Escalate to DNS or transparent interception only when proxy capture is proven insufficient.

- **P0-C1 — Bazzite client bootstrap and passive connection topology.** *Complete* for the
  Linux/Proton platform. Passive metadata only: which domains the client contacts, in what order,
  over which protocol, owned by which process. Tooling in `tools/capture/linux/`, evidence in
  `evidence/p0c1_passive_connection_topology/`, summary in `docs/CLIENT_BOOTSTRAP_TOPOLOGY.md`.
  Established a distinct `*.svc.halowaypoint.com` title-service layer, an identity-before-title
  bootstrap order, MPSD contact from the game process, UDP/3075 QoS probing across 15 Azure
  regions, and UDP/3478 traffic to Halo-operated TURN relays. Promoted no hypothesis.
- **P0-C2A — Bazzite HTTPS visibility and trust-path validation.** *Complete.* Established that a
  native Linux client, a Proton/Wine WinHTTP client, and MCC itself all honour an explicit proxy
  (MCC and the Wine client only via `http_proxy`/`https_proxy`), and that the Proton prefix has its
  own Root certificate store writable without administrative privilege. MCC certificate acceptance
  and pinning left **unresolved**. `evidence/p0c2a_https_visibility/`, `docs/HTTPS_VISIBILITY.md`.
- **P0-C2B — Read-only MCC title-service request/response capture.** *Complete, with no capture
  taken.* In both tested explicit-proxy configurations, Xbox sign-in failed despite every identity
  host being blind-tunnelled with zero decryption, so Stage B was never eligible. Narrowed H-007.
  `evidence/p0c2b_title_service_capture/`, `docs/TITLE_SERVICE_CAPTURE.md`.
- **P0-C2C — Post-authentication single-host title-service interception.** *Complete, with no
  exchange captured.* Direct sign-in succeeds with no proxy, and an exact-host post-boot redirect
  affected exactly one host with identity untouched, but MCC reused a persistent boot-time connection
  to the settings service and never contacted the observer. Certificate acceptance/pinning remain
  unresolved. Further narrowed H-007. `evidence/p0c2c_post_auth_interception/`,
  `docs/POST_AUTH_INTERCEPTION.md`.
- **P0-C2D0 — Pre-launch interception tooling hardening.** *R1 corrected after the Codex Sol
  adversarial audit; a separate Meta Muse Spark 1.2 read-only audit remains pending; synthetic
  validation only.* Codex Sol returned `C. REJECT — RELAY SAFETY FAILURE` for the first local
  candidate and identified redirect rollback, Wine-trust, metadata,
  schema, TLS-observer, preflight, and documentation blockers. R1 corrects and tests each finding.
  The HTTP reverse proxy remains explicitly `NOT READY` with no runnable network path.
  `evidence/p0c2d0_prelaunch_tooling/`, `docs/PRELAUNCH_INTERCEPTION.md`.
- **P0-C2D0-R2 — Live-preflight contract correction.** *Complete; synthetic validation only.* A first
  P0-C2D live attempt halted at its starting gate, before the direct baseline, and changed no system
  or client state. Three structural gaps were exposed: the preflight required a one-commit-ahead
  repository (the authorized live state is 0/0), it unconditionally required certificate material the
  blind-relay rung forbids, and no upstream TLS probe existed. Steam running was a fourth finding, an
  operator precondition rather than a defect. R2 makes Git expectations and the certificate stage
  explicit, adds `upstream_probe.py`, and reconciles the relay's live bounds and dead-relay
  behaviour. The accepted P0-C2D0 audit did not catch the structural gaps; it tested the synthetic
  contract, not the live rung's state and scope. `evidence/p0c2d0r2_live_preflight_correction/`,
  `docs/PRELAUNCH_INTERCEPTION.md`.
- **P0-C2D — Pre-launch settings interception live experiment.** *Complete: `A. BLIND RELAY PASS`.*
  MCC completed cached Microsoft/Xbox identity, contacted exactly
  `settings.svc.halowaypoint.com` through an opaque relay on `127.0.0.77:443`, exchanged encrypted
  bytes bidirectionally (4,728 client-to-upstream; 29,226 upstream-to-client), and reached the main
  menu without a certificate or service error. Exact rollback completed before relay expiry and a
  separate normal launch succeeded (`E-P0C2D-001` through `E-P0C2D-005`,
  `evidence/p0c2d_live_blind_relay/`). This proves transport and pre-launch reachability only; it
  does not establish plaintext, schema, settings authority, CA acceptance, or pinning.
- **P0-C2D1 — Exact-host TLS/SNI/ALPN observation live experiment.** *Complete for the bounded
  certificate-acceptance question: `A. TLS CERTIFICATE ACCEPTED`.* The historical attempt remains
  classified `E. SNI / OBSERVER CONTRACT FAILURE` because its observer expired before launch.
  Retry 1 used the accepted remaining-runtime gate and launched with 188.894 seconds left. MCC made
  eight exact-SNI TLS 1.2 connections using `ECDHE-RSA-AES256-GCM-SHA384`, negotiated no ALPN, and
  sent application data after every handshake. Exact hosts rollback, trust removal, certificate
  deletion, and normal post-rollback operation all succeeded. The observer supplied no service
  response, so this is certificate-acceptance evidence, not a working server or passthrough result.
  `E-P0C2D1R1LIVE-001` through `E-P0C2D1R1LIVE-007`,
  `evidence/p0c2d1_tls_observation_retry1/`.
- **P0-C2D1-R0 — TLS observer live-bounds correction.** *Complete; synthetic validation only.* The
  observer's `MAX_SECONDS` was 120 s, a synthetic-era value never reconciled with live launch
  behaviour, while the measured redirect-verify-to-connect interval alone is 75 s (`E-P0C2D-004`)
  and the observer's clock starts before that interval. An expired observer would have produced a
  result reading as `D. OBSERVER NOT CONTACTED` — a claim about MCC — and left the redirect pointing
  at a dead listener. The hard maximum now equals the relay's already-accepted 300 s, the
  recommended live runtime is 240 s with a connection cap of 8, and every run records `exit_reason`
  so a cap-bounded or expired run can never read as a complete one. A second finding is recorded as
  a runbook ordering requirement rather than a tool defect: the `tls-observer` preflight stage
  requires certificate material, so the exact-host certificate must be generated into scratch before
  the preflight runs. `evidence/p0c2d1r0_observer_bounds_correction/`, `docs/PRELAUNCH_INTERCEPTION.md`.
- **P0-C2D1-R1 — Remaining-runtime gate and retry contract.** *Complete; synthetic validation
  only.* Commit `ed9e323` remains the historical partial-live outcome-E attempt: its observer
  expired before client contact, produced no TLS trust verdict, and was fully restored. R1 adds
  owned monotonic run/deadline metadata, a fail-closed launch decision requiring the exact live
  observer/listener identity and at least 150 seconds remaining, and a machine-recorded direct
  baseline decision requiring identity, main-menu, error-free, and clean-shutdown assertions. A
  failed launch-window decision mandates rollback without starting Steam/MCC and is classified as a
  pre-launch safety abort. The later retry used this gate successfully; R1 remains a synthetic
  tooling correction and commit `ed9e323` remains the unchanged historical failed-window record.
  `evidence/p0c2d1r1_remaining_runtime_correction/`, `docs/PRELAUNCH_INTERCEPTION.md`.
- **P0-C2E — MCC endpoint manifest and configuration-surface discovery.** *Not started.* Depends on
  evidence from an authorized P0-C2D live experiment; must not assume a redirect intercepts a reused
  connection or that the settings service is a manifest authority.

### P0-D: Cold-boot service inventory
Capture DNS, TLS SNI, HTTP(S), WebSocket, AMQP if present, STUN/TURN/ICE, and UDP flows from a fresh profile. Identify manifests before enumerating endpoints manually.

### P0-E: Authentication map
Document observed MSA, Xbox user authentication, XSTS, Halo title-token, clearance/configuration, token lifetimes, relying parties, and failure behavior. Never commit live tokens.

### P0-F: Two-client transport adjudication
Capture invite, join, peer-hosted custom game, CGB host/join, and dedicated allocation/configuration. Determine the actual role of MPSD, secure device addresses, ICE candidates, relay services, and direct UDP.

### P0-G: UDS feasibility audit
Perform static and dynamic inspection of the owned retail PC build for server-mode strings, exports, launch flags, game-library roles, headless paths, allocator/configuration protocol references, and code reachability. Verdict must be `present/reachable`, `present/incomplete`, `absent`, or `insufficient evidence`.

### P0-H: Independent audit
Qwen performs a read-only audit of claims against the evidence ledger. All disagreement is adjudicated before implementation.

## P1 — Cold boot on a local compatibility stack
Implement only the minimum service responses needed for offline sign-in state, configuration, service record rendering, and clean error-free menus. Use local synthetic identities; do not forge Microsoft-issued credentials.

## P2 — Two clients establish a private session
Implement presence/session coordination and transport bootstrapping for two controlled clients. This phase must resolve whether the target path can use peer-hosting, a private server, or both.

## P3 — Custom games and Forge
Restore end-to-end private custom-game and Forge workflows, including host migration/failure behavior where observed.

## P4 — Custom Game Browser
Build a private directory over the proven host model: UDS-compatible instances only if P0-G proves feasibility; otherwise peer-hosted entries.

## P5 — Matchmaking
Implement private hoppers, tickets, pairing, host/server selection, session writes, and deterministic test skill values. Competitive ranking is optional.

## P6 — Progression and statistics
Implement private match result ingestion, service records, XP, unlock state, and explicit trust labeling for peer-hosted results.

## P7 — File share
Implement the observed file metadata and content-storage behavior for private user-generated content.
