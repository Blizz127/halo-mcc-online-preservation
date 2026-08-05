# Capture matrix

## Capture lanes

For every scenario, collect synchronized artifacts where possible:

- Wireshark packet capture as network ground truth
- Decrypted HTTP capture when technically and legally available
- DNS query log
- Process/module list and timestamps
- MCC client log files
- UI video or timestamped screenshots
- Sanitized request/response fixtures
- Hashes and metadata for every local artifact

Raw captures remain local. Only redacted fixtures and manifests are committed.

## Scenarios

| ID | Scenario | Accounts/machines | Required outcome |
|---|---|---:|---|
| C-001 | Fresh-profile cold boot and sign-in | 1 / 1 | Complete domain and initial service inventory |
| C-002 | Every top-level menu and title submenu | 1 / 1 | Configuration/content fetch map |
| C-003 | Peer-hosted custom game create/join/leave | 2 / 2 | Session document and transport path |
| C-004 | Campaign co-op create/join/leave | 2 / 2 | Compare peer-host behavior to custom games |
| C-005 | Forge create/join/save | 2 / 2 | Session plus UGC metadata/content behavior |
| C-006 | CGB list/filter/details | 1 / 1 | Browser directory endpoints and schemas |
| C-007 | CGB host/join/complete | 2 / 2 | Allocation, configuration, connection, and result flow |
| C-008 | Social matchmaking lifecycle | 2 / 2 | Ticket, pairing, UDS allocation/configuration, result flow |
| C-009 | Ranked matchmaking lifecycle | 2 / 2 | Skill/rank-specific calls and trusted-result behavior |
| C-010 | Firefight lifecycle | 2 / 2 | Title-specific differences |
| C-011 | Invite send/accept/decline/expiry | 2 / 2 | Presence, notification, and session transition behavior |
| C-012 | File share upload/download/delete | 2 / 2 | Metadata, storage, authorization, and content-addressing behavior |
| C-013 | Match completion and progression | 1+ / 1+ | Result submission, XP, challenge, unlock, service record |
| C-014 | Service returns 401/403/404/409/412/429/500/503 | 1 / 1 | Retry, cache, fallback, and user-facing error behavior |
| C-015 | Expired title token during idle/menu/session | 1 / 1 | Refresh and failure behavior |
| C-016 | Dedicated allocation failure | 2 / 2 | Verify fallback or terminal error behavior |

## Minimum metadata per capture

- UTC start/end
- Local timezone
- Machine ID alias
- Account alias, never gamertag/XUID in committed files
- MCC storefront, build, executable hashes, EAC mode
- Scenario ID and exact operator actions
- Capture-tool versions and filters
- Expected and observed result
- Redaction status
