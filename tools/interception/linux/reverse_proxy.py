"""Audited P0-C2D reverse-proxy components -- PASSTHROUGH NOT READY.

The inherited prototype buffered complete HTTP messages, did not correctly
handle persistent connections, informational responses, upgrades, trailers, or
all half-close cases, and could outlive its nominal server deadline. Those
properties are not a proven safe HTTP/1.1 passthrough. The runnable network path
has therefore been removed. This module retains only value-free metadata
helpers and an explicit status response; invoking it fails closed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exclusions import safe_header_names  # noqa: E402
import schema_extract  # noqa: E402

STATUS = "NOT READY"
BLOCKERS = (
    "streaming HTTP/1.1 framing is not implemented",
    "persistent requests and responses are not implemented",
    "upgrade, trailer, informational-response, and close-delimited cases are unproven",
    "bidirectional deadline and half-close behavior is unproven for terminated TLS",
)


class PassthroughNotReady(RuntimeError):
    pass


def request_metadata(method: str, target: str, header_names: Iterable[str],
                     body_length: int) -> dict:
    """Build value-free metadata; accepts names and lengths, never header/body values."""
    if body_length < 0:
        raise ValueError("body_length cannot be negative")
    return {
        "method": schema_extract.normalize_http_method(method),
        **schema_extract.normalize_request_target(target),
        "request_header_names": safe_header_names(header_names),
        "request_body_length": body_length,
    }


def response_metadata(status: int | None, header_names: Iterable[str],
                      body_length: int) -> dict:
    if body_length < 0:
        raise ValueError("body_length cannot be negative")
    return {
        "status": status,
        "response_header_names": safe_header_names(header_names),
        "response_body_length_on_wire": body_length,
    }


def readiness() -> dict:
    return {
        "component": "p0c2d-reverse-proxy",
        "status": STATUS,
        "network_path_present": False,
        "blockers": list(BLOCKERS),
    }


def serve(*_args, **_kwargs):
    raise PassthroughNotReady("reverse proxy is NOT READY; no network listener was created")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", action="store_true", help="print machine-readable readiness")
    args = parser.parse_args()
    print(json.dumps(readiness(), indent=2))
    return 0 if args.status else 2


if __name__ == "__main__":
    raise SystemExit(main())
