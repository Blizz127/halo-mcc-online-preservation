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
- **P0-C2D — MCC endpoint manifest and configuration-surface discovery.** *Not started, requires its
  own authorization.* Must not assume a redirect intercepts a reused connection: needs a trigger
  proven to force a fresh settings fetch, or a mechanism acting before the connection is established
  without running identity under interception.

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
