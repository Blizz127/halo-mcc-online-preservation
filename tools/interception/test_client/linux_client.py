"""Native Linux HTTPS test client for Stage A.

Exercises the four cases the rung needs to distinguish, and reports the outcome
as structured data rather than a pass/fail, because *how* a TLS attempt failed
is the evidence:

1. no trust        - expect a verification failure naming an unknown issuer
2. explicit trust  - expect success once the local CA is supplied
3. via proxy       - expect success through an explicit proxy
4. system trust    - whether the host trust store alone is sufficient

Never sends credentials and only ever targets the reserved test domain or an
explicitly supplied local address.
"""

from __future__ import annotations

import argparse
import http.client
import json
import socket
import ssl
from pathlib import Path


def attempt(host: str, port: int, ca_file: Path | None, proxy: tuple[str, int] | None,
            server_hostname: str | None = None, timeout: float = 10.0) -> dict:
    result = {
        "target": f"{host}:{port}",
        "sni": server_hostname or host,
        "ca_file_supplied": bool(ca_file),
        "proxy": f"{proxy[0]}:{proxy[1]}" if proxy else None,
        "tls_completed": False,
        "tls_version": None,
        "status": None,
        "body_length": None,
        "error_class": None,
        "error_detail": None,
    }

    context = ssl.create_default_context()
    if ca_file:
        context.load_verify_locations(cafile=str(ca_file))

    try:
        if proxy:
            conn = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
            conn.set_tunnel(host, port)
            conn.sock = socket.create_connection(proxy, timeout=timeout)
            conn._tunnel()
            conn.sock = context.wrap_socket(conn.sock, server_hostname=server_hostname or host)
        else:
            raw = socket.create_connection((host, port), timeout=timeout)
            wrapped = context.wrap_socket(raw, server_hostname=server_hostname or host)
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
            conn.sock = wrapped

        result["tls_completed"] = True
        result["tls_version"] = conn.sock.version()
        conn.request("GET", "/p0c2a-test", headers={"User-Agent": "p0c2a-linux-test-client"})
        response = conn.getresponse()
        result["status"] = response.status
        # Length only; the body itself is synthetic but is never recorded.
        result["body_length"] = len(response.read())
        conn.close()
    except ssl.SSLCertVerificationError as exc:
        result["error_class"] = "SSLCertVerificationError"
        result["error_detail"] = getattr(exc, "verify_message", None) or str(exc.reason)
    except ssl.SSLError as exc:
        result["error_class"] = "SSLError"
        result["error_detail"] = str(getattr(exc, "reason", exc))
    except OSError as exc:
        result["error_class"] = type(exc).__name__
        result["error_detail"] = str(exc)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="p0c2a.test")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca", type=Path, default=None)
    parser.add_argument("--proxy-host", default=None)
    parser.add_argument("--proxy-port", type=int, default=None)
    parser.add_argument("--connect-to", default=None,
                        help="dial this address instead of resolving --host (SNI stays --host)")
    args = parser.parse_args()

    proxy = (args.proxy_host, args.proxy_port) if args.proxy_host else None
    dial_host = args.connect_to or args.host
    print(json.dumps(attempt(dial_host, args.port, args.ca, proxy, server_hostname=args.host), indent=2))
