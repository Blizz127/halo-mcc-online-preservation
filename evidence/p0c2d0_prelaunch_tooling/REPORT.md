# P0-C2D0-R1 report: pre-launch interception tooling correction

**Outcome: Codex Sol returned `C. REJECT — RELAY SAFETY FAILURE` for the first local candidate.
P0-C2D0-R1 corrects every reported blocker and passes an expanded synthetic contract. A separate
Meta Muse Spark 1.2 read-only audit remains pending. No live experiment ran. The HTTP reverse proxy
remains explicitly `NOT READY`.**

## E-P0C2D0-001 — inherited-file provenance and treatment

Two untracked prototypes existed before the implementing Codex session; they were not created by
that session. They were adopted as authorized working-tree inputs only after a read-only provenance
audit found no active writer, process holder, sensitive content, or captured production data.

| Inherited file | Original SHA-256 | Original size and mtime | Treatment |
|---|---|---|---|
| `tools/interception/linux/tcp_relay.py` | `54f5d08610ec55453d8846fc14175c056e3407b408d4e2e226c1a966833a66c1` | 6,330 bytes; `2026-08-05 23:54:55.866420474 -0500` | Renamed to `prelaunch_relay.py` and substantially rewritten. Reuse was limited to the core two-socket blind-pump structure, directional-counter concept, and per-direction EOF/`SHUT_WR` behavior. This is structural reuse, not a line-for-line preservation claim. |
| `tools/interception/linux/reverse_proxy.py` | `96c79984a1eaeb67c6d5829507589e74ce800fde5399b9c9d6abc8c0d9509d04` | 13,197 bytes; `2026-08-05 23:57:15.258439962 -0500` | Rewritten down to non-runnable audited helpers. No listener, TLS termination, HTTP parser, or forwarding path was retained. Reuse is minimal and conceptual: value-free metadata and readiness reporting behind an unconditional `NOT READY` failure. |

The original hashes and timestamps remain recorded to distinguish adoption from authorship.

## E-P0C2D0-R1-001 — Codex Sol adversarial rejection and relay correction

The first local candidate (`fb0ebd3934de354734ebd526bbba8714d49ba57e`) passed its committed
tests but failed the Codex Sol adversarial audit. Codex Sol found that recognized stale controls were not
removed, `EADDRINUSE` escaped as a raw exception after creating a log, and cleanup did not prove
control-file ownership.

R1 now binds and listens before creating any output; initializes the payload-free log; atomically
publishes complete PID/ready JSON through same-directory staging and hard-link creation; records the
same PID and unique run ID in both controls; refuses active or unrelated state; removes only
format/tool/kind-valid stale state whose PID is absent or not the expected tool; and removes owned
controls only when device, inode, and exact contents still match. Replaced paths are preserved.
`EADDRINUSE` returns a concise safety error with no new log/PID/ready artifact. Relay writes use
deadline/idle-bounded `send`, half-close remains directional, clients are forcibly closed at the
total deadline, and daemon workers receive one shared bounded join window.

## E-P0C2D0-R1-002 — exact-line redirect rollback

The first candidate could restore a whole prior hosts file after checking only the inode, discarding
unrelated concurrent changes. R1 records original SHA-256, inode, size, exact authorized line,
sentinel, normalized hostname, address, and exact bytes. It requires exactly one exact project line,
removes only that line in memory, and requires every remaining byte to equal the original. Missing,
duplicate, edited, or concurrently appended state fails before payload creation. The successful
in-place command is guarded by current hash and inode; verification requires original hash/size,
unchanged inode, exact bytes, and sentinel absence. The emergency command likewise removes only one
exact authorized line and preserves all other bytes.

## E-P0C2D0-R1-003 — Wine trust and metadata/schema correction

Wine trust now accepts only exactly 40 hexadecimal thumbprint characters. Installation returns the
required `verified_present` field after an exact successful query. Removal fails on delete error,
ambiguous query error, or continued exact-key presence; `verified_absent` is true only after an
explicit successful not-found result. Tests inject every registry outcome and never start Wine.

One shared conservative opaque-identifier classifier now covers request paths, host labels, and JSON
keys. It strips fragments first; decodes percent encoding once for classification only; discards all
query values; and redacts email, UUID, JWT/dotted token, Xbox-authorization, SteamID64/XUID, long hex,
base64/base64url including all-letter values, long alphabetic identifiers, and mixed opaque session
values. Dynamic keys receive deterministic collision-safe placeholders; original keys cannot enter
the schema or synthetic fixture.

## E-P0C2D0-R1-004 — TLS observer and read-only preflight correction

Production observation requires exact selected-host SNI. Missing or mismatched SNI is safely
classified and closed before application reads. Negotiated `h2` records
`protocol_result: unsupported_protocol`, reads at most one discarded byte to classify application
data presence, and performs no HTTP/2 parsing. Certificate verdict is explicit, and
`accepted_certificate` requires post-handshake application data rather than server-side TLS
completion alone. Relay-owned control and bind-failure lifecycle is reused.

The read-only preflight now checks configurable branch/HEAD/parent/remote tip, clean tracked and
nonignored-untracked state, exact ahead/behind relationship, proxy variables, production listener
absence through `/proc/net/tcp`, project/capture/MCC processes, Steam policy, project hosts sentinels,
manual selected-host entries, selected-host IPv4/IPv6, all six identity hosts, exact CA absence via
read-only `system.reg`, required tools, and repository-external non-symlink scratch/output paths. Git
queries disable optional locks. It never binds, edits, starts Wine, or terminates anything.

## E-P0C2D0-R1-005 — reverse proxy and interpretation boundary

`reverse_proxy.py` remains `NOT READY`; `serve()` raises before creating a listener. Streaming
HTTP/1.1 framing, persistence, upgrades, trailers, informational responses, close-delimited cases,
and terminated-TLS half-close/deadline behavior remain deferred.

Validation is recorded in `validation.txt`. Tests use invented values, reserved names, temporary
files, and loopback high ports only. No test contacted Microsoft, Xbox, Steam, Epic, PlayFab, Halo,
or another production service. No test invoked `sudo`, changed `/etc/hosts`, DNS, routing, firewall,
proxy, Wine, or a certificate store, or started Steam/MCC/Wine.

Established: the R1 tooling passes its expanded synthetic contract and is ready for a second
independent read-only audit.

Not established: any MCC request/response, TLS acceptance or pinning verdict, settings manifest,
endpoint authority, production forwarding behavior, or live-experiment result. P0-C2D is not
started. P0-C2E manifest discovery is not started.
