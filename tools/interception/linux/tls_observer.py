"""Local TLS observer: records handshake metadata, never request/response bodies.

Purpose is diagnostic only. It answers a narrow set of questions:

- did a client reach this address at all?
- what SNI did it present?
- did it complete the TLS handshake, or reject the certificate?
- if it rejected, which TLS alert did it send?

The alert is the interesting part. A client that does not trust the issuing CA
sends `unknown_ca`; a client that trusts the CA but expected a specific
certificate (pinning) typically sends `bad_certificate` or
`certificate_unknown` **after** the CA would otherwise have validated. Those are
different observable outcomes and this tool records which occurred rather than
collapsing both into "it failed".

What it deliberately does not do:

- It never reads a request body, and never logs a header **value** — only header
  names, which cannot carry a token.
- It never returns a response that could be mistaken for the real service. The
  Stage D response is an explicit `501` identifying itself as a local observer,
  so the client cannot be fed a plausible-looking success and no modified
  traffic is ever forwarded to an official service.
"""

from __future__ import annotations

import datetime
import json
import socket
import ssl
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exclusions import safe_header_names  # noqa: E402

SYNTHETIC_STAGE_A_BODY = json.dumps({
    "service": "p0c2a-local-test",
    "note": "synthetic response from a local test server; not related to any real service",
    "value": 1234,
}).encode()

STAGE_D_BODY = json.dumps({
    "observer": "p0c2a-local-tls-observer",
    "note": "This is a local diagnostic observer. It is not the real service and "
            "intentionally does not emulate one.",
}).encode()


class Observation(dict):
    pass


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def run_observer(
    certfile: Path,
    keyfile: Path,
    port: int = 8443,
    bind: str = "127.0.0.1",
    mode: str = "stage_a",
    max_connections: int | None = None,
    log_path: Path | None = None,
    ready_event: threading.Event | None = None,
) -> list[Observation]:
    """Serve TLS on bind:port, recording metadata for each connection."""
    observations: list[Observation] = []

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))

    seen_sni: dict[int, str | None] = {}

    def sni_callback(sslsock, server_name, sslctx):
        seen_sni[id(sslsock)] = server_name

    context.sni_callback = sni_callback

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind, port))
    listener.listen(8)
    listener.settimeout(1.0)

    if ready_event is not None:
        ready_event.set()

    handled = 0
    try:
        while max_connections is None or handled < max_connections:
            try:
                raw, peer = listener.accept()
            except TimeoutError:
                continue
            handled += 1
            record = Observation({
                "timestamp": _now(),
                "client_address": peer[0],
                "client_port": peer[1],
                "sni": None,
                "tls_completed": False,
                "tls_version": None,
                "cipher": None,
                "alert": None,
                # Under TLS 1.3 the server completes its side of the handshake
                # before the client has validated the certificate, so
                # `tls_completed` alone does NOT mean the client accepted it. A
                # client that rejects the certificate afterwards simply closes
                # without sending a request. `client_sent_request` is therefore
                # the reliable acceptance signal, not `tls_completed`.
                "client_sent_request": False,
                "client_verdict": None,
                "request_method": None,
                "request_path": None,
                "request_header_names": [],
                "response_status": None,
                "response_body_length": None,
            })
            try:
                raw.settimeout(10.0)
                tls = context.wrap_socket(raw, server_side=True)
                record["sni"] = seen_sni.get(id(tls))
                record["tls_completed"] = True
                record["tls_version"] = tls.version()
                cipher = tls.cipher()
                record["cipher"] = cipher[0] if cipher else None

                # Read only the request head, never the body.
                head = b""
                while b"\r\n\r\n" not in head and len(head) < 16384:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                if head:
                    record["client_sent_request"] = True
                    record["client_verdict"] = "accepted_certificate"
                    lines = head.split(b"\r\n\r\n", 1)[0].decode("latin-1").splitlines()
                    if lines:
                        parts = lines[0].split()
                        if len(parts) >= 2:
                            record["request_method"] = parts[0]
                            record["request_path"] = parts[1]
                    names = [ln.split(":", 1)[0] for ln in lines[1:] if ":" in ln]
                    record["request_header_names"] = safe_header_names(names)
                else:
                    # Handshake finished server-side, then the peer went away
                    # without asking for anything: a post-handshake rejection.
                    record["client_verdict"] = "rejected_after_handshake"

                if mode == "stage_a":
                    body, status = SYNTHETIC_STAGE_A_BODY, b"200 OK"
                else:
                    body, status = STAGE_D_BODY, b"501 Not Implemented"
                tls.sendall(
                    b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                record["response_status"] = status.decode().split()[0]
                record["response_body_length"] = len(body)
                tls.close()
            except ssl.SSLError as exc:
                # The client refused our certificate. Which alert it sent is the
                # distinguishing evidence between "CA not trusted" and "pinned".
                reason = getattr(exc, "reason", None)
                record["alert"] = reason or f"{type(exc).__name__}"
                record["client_verdict"] = (
                    "rejected_during_handshake" if not record["tls_completed"]
                    else "rejected_after_handshake"
                )
            except (OSError, ValueError) as exc:
                record["alert"] = f"{type(exc).__name__}: {exc}"
                if record["client_verdict"] is None:
                    record["client_verdict"] = "connection_error"
            finally:
                observations.append(record)
                if log_path is not None:
                    Path(log_path).write_text(json.dumps(observations, indent=2), encoding="utf-8")
                try:
                    raw.close()
                except OSError:
                    pass
    finally:
        listener.close()
    return observations


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--mode", choices=("stage_a", "stage_d"), default="stage_a")
    parser.add_argument("--max-connections", type=int, default=None)
    parser.add_argument("--log", type=Path, default=None)
    args = parser.parse_args()

    result = run_observer(
        args.cert, args.key, args.port, args.bind, args.mode, args.max_connections, args.log
    )
    print(json.dumps(result, indent=2))
