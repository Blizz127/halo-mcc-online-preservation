# P0-C2D pre-launch interception tooling

Status: **P0-C2D0-R1 corrected after the Codex Sol adversarial audit; a separate Meta Muse Spark 1.2
read-only audit remains pending; P0-C2D live experiment not started.** Codex Sol returned
`C. REJECT — RELAY SAFETY FAILURE` for the first local candidate and identified additional redirect, Wine-trust, metadata,
schema, TLS-observer, preflight, and documentation blockers. R1 corrects and synthetically tests
each finding. No production service was contacted and no host, DNS, routing, firewall, proxy,
Wine, Steam, MCC, or certificate-store state was changed.

## Safety boundary

- `prelaunch_relay.py` is the only ready forwarding component. Its CLI accepts exactly
  `127.0.0.77:443`, `settings.svc.halowaypoint.com`, a numeric global-unicast upstream IPv4 address,
  bounded runtime/connection counts, and explicit log/PID/ready paths. It performs no DNS and never
  terminates TLS or persists payload bytes. It binds/listens before creating artifacts, publishes
  atomic PID/ready controls with a per-run identifier, removes only recognized stale controls,
  preserves replaced/unrelated paths, bounds every write, and closes/joins workers by deadline.
- `host_redirect.py` changes nothing itself. It rejects duplicates, checks IPv4 and IPv6, requires
  all six identity hosts to resolve away from the observer, and records the original hash, inode,
  size, exact inserted line, sentinel, host, and address. Rollback removes exactly one authorized
  line in memory, proves every remaining byte equals the recorded pre-state, refuses concurrent or
  ambiguous changes, guards the in-place write with current hash/inode, and verifies final
  hash/size/inode plus sentinel absence. Its emergency command also removes only that exact line.
- `local_ca.py` writes only outside the repository through a non-symlink directory, allows at most
  two days, and permits a real-host certificate only for `settings.svc.halowaypoint.com` with a
  critical exact-name constraint. `wine_trust.py` validates a 40-hex thumbprint, requires exact
  post-install presence, and treats delete failure, query failure, or continued presence as a
  removal failure.
- `p0c2d_preflight.py` is read-only and checks the expected Git graph/cleanliness, proxy variables,
  listener and project-process absence, Steam policy, hosts/sentinel/manual-override state, selected
  and six-host identity resolution, exact CA absence, required tools, and repository-external
  scratch/output paths. It parses `/proc`, Git output, `/etc/hosts`, DNS results, and `system.reg`
  without binding, starting Wine, or changing state.
- `tls_observer.py` is bounded, records TLS/SNI/ALPN and value-free HTTP/1.1 metadata, never forwards,
  and never persists peer addresses, header values, query values, opaque path/host identifiers, or
  bodies. Production SNI must match the selected hostname; missing/mismatched SNI is closed before
  application parsing. `h2` is explicitly `unsupported_protocol` and is never parsed. Certificate
  acceptance requires post-handshake application data. It shares the relay's owned-control lifecycle.
- `reverse_proxy.py` is explicitly **NOT READY**. Its inherited runnable forwarder was removed because
  safe streaming HTTP/1.1 framing, persistent exchanges, upgrades/trailers/informational responses,
  and TLS half-close/deadline behavior are not proven.

Synthetic tests use only loopback addresses and high unprivileged ports. The production CLI paths
are not exercised by the test suite.

## Phase boundary

P0-C2D0-R1 establishes only that the corrected tooling obeys its synthetic safety contract. It does not
establish MCC certificate acceptance, pinning, request shape, response schema, settings authority,
or endpoint-manifest behavior. Those remain for the separately authorized P0-C2D live experiment
and subsequent P0-C2E manifest discovery.
