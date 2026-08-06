"""Explicit HTTP/HTTPS proxy that records connection metadata only.

Two modes, and the default is the safe one:

- `tunnel` (**default**) — every `CONNECT` is passed through as an opaque TCP
  tunnel. TLS is never terminated, so nothing is decrypted and there is no
  plaintext to leak. The SNI is still recorded, because it is readable from the
  ClientHello without decrypting anything. This mode answers the primary Stage C
  question — *does the client use the proxy at all?* — at zero decryption risk.
- `terminate` — TLS is terminated with the local test CA so request metadata is
  visible. Used only against the local Stage A test service, and in Stage D
  against one deliberately chosen non-identity host.

**Excluded hosts are always tunnelled, in either mode.** The check happens
before any mode branch, so no configuration error or future edit to the
terminate path can cause an identity or token host to be decrypted. Exclusion is
structural, not a filter applied after the fact.

Nothing here ever reads, buffers, or logs a request or response **body**, and no
header **value** is recorded — only header names. Those two properties hold by
construction rather than by redaction, so a logging mistake cannot produce a
credential in the output.
"""

from __future__ import annotations

import datetime
import json
import select
import socket
import socketserver
import ssl
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exclusions import is_excluded, redact_text, safe_header_names  # noqa: E402
import schema_extract  # noqa: E402

# SNI parsing is reused from the P0-C1 pcap tooling rather than reimplemented,
# so both rungs agree on how a ClientHello is read.
_CAPTURE_TOOLS = Path(__file__).resolve().parents[2] / "capture" / "linux"
if str(_CAPTURE_TOOLS) not in sys.path:
    sys.path.insert(0, str(_CAPTURE_TOOLS))
from pcap_parse import parse_tls_client_hello_sni  # noqa: E402

_LOG_LOCK = threading.Lock()


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


class ProxyState:
    def __init__(self, mode: str, log_path: Path | None, cert: Path | None, key: Path | None,
                 terminate_hosts: set[str] | None):
        self.mode = mode
        self.log_path = log_path
        self.cert = cert
        self.key = key
        # When set, only these hosts are terminated; everything else tunnels.
        self.terminate_hosts = terminate_hosts or set()
        self.records: list[dict] = []

    def record(self, entry: dict) -> None:
        with _LOG_LOCK:
            self.records.append(entry)
            if self.log_path:
                Path(self.log_path).write_text(json.dumps(self.records, indent=2), encoding="utf-8")

    def should_terminate(self, host: str) -> bool:
        """Decide whether one host may be TLS-terminated. Default is NO.

        Three independent conditions must all hold, checked in this order so the
        safety-relevant ones cannot be skipped:

        1. the host is not on the hard-exclusion denylist,
        2. the proxy was explicitly started in terminate mode, and
        3. the host appears **verbatim** in the decrypt allowlist.

        The allowlist is an exact set-membership test on the normalized host,
        never a suffix or prefix match: `settings.svc.halowaypoint.com.evil.test`
        does not match an allowlisted `settings.svc.halowaypoint.com`. An empty
        allowlist terminates nothing, so forgetting to configure it fails closed
        rather than decrypting everything.
        """
        candidate = (host or "").strip().lower().rstrip(".")
        if not candidate:
            return False
        if is_excluded(candidate):
            return False
        if self.mode != "terminate":
            return False
        return candidate in self.terminate_hosts


class ProxyHandler(socketserver.StreamRequestHandler):
    timeout = 30
    state: ProxyState = None  # injected by build_server

    def handle(self) -> None:
        try:
            request_line = self.rfile.readline(65536).decode("latin-1").strip()
        except (OSError, UnicodeDecodeError):
            return
        if not request_line:
            return

        parts = request_line.split()
        if len(parts) < 3:
            return
        method, target = parts[0], parts[1]

        headers = []
        while True:
            try:
                line = self.rfile.readline(65536).decode("latin-1")
            except (OSError, UnicodeDecodeError):
                return
            if not line or line in ("\r\n", "\n"):
                break
            if ":" in line:
                headers.append(line.split(":", 1)[0])

        if method.upper() == "CONNECT":
            host, _, port_str = target.rpartition(":")
            try:
                port = int(port_str)
            except ValueError:
                host, port = target, 443
            self._handle_connect(host, port, headers)
        else:
            # Plain HTTP through the proxy: record metadata, do not forward a
            # body, and do not fetch on the client's behalf.
            target_metadata = schema_extract.normalize_request_target(target)
            self.state.record({
                "timestamp": _now(),
                "event": "http_request_seen",
                "method": schema_extract.normalize_http_method(method),
                **target_metadata,
                "request_header_names": safe_header_names(headers),
                "note": "plain-HTTP request observed; not forwarded",
            })
            self.wfile.write(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")

    def _handle_connect(self, host: str, port: int, header_names: list[str]) -> None:
        excluded = is_excluded(host)
        entry = {
            "timestamp": _now(),
            "event": "connect",
            "target_host": schema_extract.normalize_hostname(host),
            "target_port": port,
            "excluded_from_inspection": excluded,
            "action": None,
            "sni": None,
            "connect_header_names": safe_header_names(header_names),
        }

        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError as exc:
            entry["action"] = "upstream_connect_failed"
            entry["error"] = type(exc).__name__
            self.state.record(entry)
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return

        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()

        if self.state.should_terminate(host):
            entry["action"] = "terminated_for_inspection"
            self.state.record(entry)
            self._terminate(upstream, host, entry)
            return

        entry["action"] = "blind_tunnel_excluded" if excluded else "blind_tunnel"
        self._tunnel(upstream, entry)

    def _tunnel(self, upstream: socket.socket, entry: dict) -> None:
        """Opaque byte relay. Peeks only the first client record for SNI.

        Half-close is handled properly rather than treated as end-of-tunnel. An
        earlier version tore down BOTH directions the first time either side
        returned zero bytes, which breaks any exchange where one peer finishes
        sending while still expecting a reply - exactly the shape of a
        multi-step authentication flow. The relay now shuts down only the
        finished direction and keeps the other open until both are done.
        """
        client = self.connection
        first = True
        open_sides = {client, upstream}
        try:
            while open_sides:
                readable, _, errored = select.select(list(open_sides), [], list(open_sides), 120)
                if errored:
                    break
                if not readable:
                    break  # idle timeout
                for sock in readable:
                    peer = upstream if sock is client else client
                    try:
                        data = sock.recv(65536)
                    except (ConnectionResetError, TimeoutError):
                        open_sides.discard(sock)
                        continue
                    if not data:
                        # This direction is finished; signal EOF onward and stop
                        # reading it, but leave the opposite direction running.
                        open_sides.discard(sock)
                        try:
                            peer.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    if first and sock is client:
                        first = False
                        # Excluded hosts: do not even inspect the ClientHello.
                        if not entry["excluded_from_inspection"]:
                            try:
                                entry["sni"] = schema_extract.normalize_hostname(
                                    parse_tls_client_hello_sni(data)
                                )
                            except Exception:
                                entry["sni"] = None
                    entry["bytes_relayed"] = entry.get("bytes_relayed", 0) + len(data)
                    try:
                        peer.sendall(data)
                    except OSError:
                        open_sides.discard(sock)
        except (OSError, ValueError):
            pass
        finally:
            self.state.record(entry)
            for sock in (upstream, client):
                try:
                    sock.close()
                except OSError:
                    pass

    def _terminate(self, upstream: socket.socket, host: str, entry: dict) -> None:
        """Terminate TLS locally to read request metadata. Never reads bodies."""
        try:
            upstream.close()
        except OSError:
            pass
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(self.state.cert), keyfile=str(self.state.key))
        try:
            tls = context.wrap_socket(self.connection, server_side=True)
        except ssl.SSLError as exc:
            entry["tls_result"] = "client_rejected_certificate"
            entry["alert"] = str(getattr(exc, "reason", type(exc).__name__))
            self.state.record(entry)
            return

        entry["tls_result"] = "client_accepted_certificate"
        entry["tls_version"] = tls.version()
        try:
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 16384:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                head += chunk
            if head:
                lines = head.split(b"\r\n\r\n", 1)[0].decode("latin-1").splitlines()
                if lines:
                    bits = lines[0].split()
                    if len(bits) >= 2:
                        entry["request_method"] = schema_extract.normalize_http_method(bits[0])
                        entry.update(schema_extract.normalize_request_target(bits[1]))
                entry["request_header_names"] = safe_header_names(
                    ln.split(":", 1)[0] for ln in lines[1:] if ":" in ln
                )
            body = b'{"observer":"p0c2a","note":"local diagnostic; not the real service"}'
            tls.sendall(b"HTTP/1.1 501 Not Implemented\r\nContent-Type: application/json\r\n"
                        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        except (OSError, ssl.SSLError, UnicodeDecodeError):
            pass
        finally:
            self.state.record(entry)
            try:
                tls.close()
            except OSError:
                pass


class ThreadedProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def build_server(port: int, state: ProxyState, bind: str = "127.0.0.1") -> ThreadedProxy:
    handler = type("BoundProxyHandler", (ProxyHandler,), {"state": state})
    return ThreadedProxy((bind, port), handler)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--mode", choices=("tunnel", "terminate"), default="tunnel")
    parser.add_argument("--cert", type=Path, default=None)
    parser.add_argument("--key", type=Path, default=None)
    parser.add_argument("--terminate-host", action="append", default=[],
                        help="restrict termination to these hosts (repeatable)")
    parser.add_argument("--log", type=Path, default=None)
    parser.add_argument("--seconds", type=float, default=None)
    args = parser.parse_args()

    if args.mode == "terminate" and not (args.cert and args.key):
        raise SystemExit("--mode terminate requires --cert and --key")
    for host in args.terminate_host:
        if is_excluded(host):
            raise SystemExit(f"refusing: {host} is on the P0-C2A exclusion list")

    state = ProxyState(args.mode, args.log, args.cert, args.key,
                       {h.lower() for h in args.terminate_host})
    server = build_server(args.port, state, args.bind)
    print(f"proxy listening on {args.bind}:{args.port} mode={args.mode}", file=sys.stderr)
    if args.seconds:
        threading.Timer(args.seconds, server.shutdown).start()
    try:
        server.serve_forever()
    finally:
        server.server_close()
        print(json.dumps(state.records, indent=2))
