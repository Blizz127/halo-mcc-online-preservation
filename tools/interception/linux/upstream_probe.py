"""Read-only upstream TLS validation for one authorized literal IPv4 candidate.

This tool answers exactly one question before any redirect exists: *does this
literal address actually terminate TLS for the selected hostname, with a
certificate the system trust store verifies?* It is the missing step-5 gate for
the P0-C2D live rung, and it is deliberately not a client.

What it does:

- dials a **literal IPv4 address** (never a name; the tool performs no DNS)
- offers the selected hostname as SNI and requires hostname verification
- advertises ALPN so the negotiated protocol is observable
- collects TLS and certificate **metadata**, then closes

What it never does:

- send an HTTP request, or any application byte at all
- write a certificate body, DER, or PEM
- accept an unverified certificate
- reach a loopback, private, link-local, multicast, reserved, documentation,
  or otherwise non-global address in production mode

Tests drive ``synthetic_probe`` against a local TLS server on loopback with a
temporary CA. That entry point refuses anything that is not loopback, refuses
low ports, and refuses the production hostname, so the production restrictions
cannot be weakened through it or through any CLI flag.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import ssl
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

AUTHORIZED_HOST = "settings.svc.halowaypoint.com"
AUTHORIZED_PORT = 443
ADVERTISED_ALPN: tuple[str, ...] = ("h2", "http/1.1")
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 30.0
DETAIL_LIMIT = 200

# Ranges that must never be probed in production. `is_global` alone is not
# sufficient: CPython reports IPv4 multicast as global, so multicast would
# otherwise pass a global-unicast-only check.
DOCUMENTATION_NETWORKS: tuple[tuple[str, str], ...] = (
    ("192.0.2.0/24", "RFC 5737 TEST-NET-1 documentation range"),
    ("198.51.100.0/24", "RFC 5737 TEST-NET-2 documentation range"),
    ("203.0.113.0/24", "RFC 5737 TEST-NET-3 documentation range"),
    ("198.18.0.0/15", "RFC 2544 benchmarking range"),
    ("233.252.0.0/24", "RFC 5771 MCAST-TEST-NET documentation range"),
    ("100.64.0.0/10", "RFC 6598 shared address space"),
)


class UpstreamProbeError(ValueError):
    """Raised when a probe target or mode violates the authorized contract."""


def _bounded(value: object) -> str:
    """Bound any diagnostic string so an unexpected payload cannot be recorded."""
    return str(value)[:DETAIL_LIMIT]


def classify_candidate_ip(value: object) -> ipaddress.IPv4Address:
    """Return the address only when it is a literal, global-unicast IPv4 address."""
    text = str(value).strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise UpstreamProbeError(
            "candidate must be a literal IPv4 address; hostnames and DNS are forbidden"
        ) from exc
    if isinstance(address, ipaddress.IPv6Address):
        raise UpstreamProbeError("candidate must be IPv4; IPv6 is not authorized")
    for network, label in DOCUMENTATION_NETWORKS:
        if address in ipaddress.ip_network(network):
            raise UpstreamProbeError(f"candidate is inside the {label}: {address}")
    disqualifiers = (
        (address.is_unspecified, "unspecified"),
        (address.is_loopback, "loopback"),
        (address.is_link_local, "link-local"),
        (address.is_multicast, "multicast"),
        (address.is_reserved, "reserved"),
        (address.is_private, "private"),
        (address == ipaddress.IPv4Address("255.255.255.255"), "broadcast"),
    )
    for disqualified, label in disqualifiers:
        if disqualified:
            raise UpstreamProbeError(f"candidate must be a public address, not {label}: {address}")
    if not address.is_global:
        raise UpstreamProbeError(f"candidate must be a global unicast IPv4 address: {address}")
    return address


def validate_production_target(hostname: str, candidate_ip: object,
                               port: int) -> ipaddress.IPv4Address:
    if (hostname or "").strip().lower().rstrip(".") != AUTHORIZED_HOST:
        raise UpstreamProbeError(f"selected hostname must be exactly {AUTHORIZED_HOST}")
    if port != AUTHORIZED_PORT:
        raise UpstreamProbeError(f"production upstream port must be {AUTHORIZED_PORT}")
    return classify_candidate_ip(candidate_ip)


def _blank_record(hostname: str, candidate: str, port: int) -> dict:
    return {
        "format": "p0c2d0r2-upstream-probe-v1",
        "selected_hostname": hostname,
        "candidate_ip": candidate,
        "port": port,
        "sni": hostname,
        "hostname_verification": True,
        "verify_mode": "CERT_REQUIRED",
        "advertised_alpn": list(ADVERTISED_ALPN),
        "application_bytes_sent": 0,
        "http_request_sent": False,
        "tls_completed": False,
        "verified": False,
        "tls_version": None,
        "cipher_name": None,
        "cipher_protocol": None,
        "cipher_bits": None,
        "negotiated_alpn": None,
        "certificate_subject": None,
        "certificate_issuer": None,
        "certificate_not_before": None,
        "certificate_not_after": None,
        "certificate_sha256_fingerprint": None,
        "error_class": None,
        "error_detail": None,
    }


def _build_context(ca_file: Path | None) -> ssl.SSLContext:
    context = ssl.create_default_context(
        cafile=str(ca_file) if ca_file is not None else None
    )
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(list(ADVERTISED_ALPN))
    return context


def _record_certificate(record: dict, der: bytes | None) -> None:
    """Derive metadata from the leaf certificate. The DER itself is never kept."""
    if not der:
        record["error_class"] = "MissingPeerCertificate"
        return
    certificate = x509.load_der_x509_certificate(der)
    record["certificate_subject"] = certificate.subject.rfc4514_string()
    record["certificate_issuer"] = certificate.issuer.rfc4514_string()
    record["certificate_not_before"] = certificate.not_valid_before_utc.isoformat()
    record["certificate_not_after"] = certificate.not_valid_after_utc.isoformat()
    record["certificate_sha256_fingerprint"] = certificate.fingerprint(hashes.SHA256()).hex(":", 1)


def _handshake(dial_host: str, port: int, server_hostname: str,
               context: ssl.SSLContext, timeout: float, record: dict) -> dict:
    """Handshake, collect metadata, close. No application byte is ever written."""
    try:
        raw = socket.create_connection((dial_host, port), timeout=timeout)
    except OSError as exc:
        record["error_class"] = type(exc).__name__
        record["error_detail"] = _bounded(exc)
        return record
    try:
        raw.settimeout(timeout)
        tls = context.wrap_socket(raw, server_hostname=server_hostname)
    except ssl.SSLCertVerificationError as exc:
        raw.close()
        record["error_class"] = "SSLCertVerificationError"
        record["error_detail"] = _bounded(getattr(exc, "verify_message", None) or exc.reason)
        return record
    except ssl.SSLError as exc:
        raw.close()
        record["error_class"] = "SSLError"
        record["error_detail"] = _bounded(getattr(exc, "reason", exc))
        return record
    except OSError as exc:
        raw.close()
        record["error_class"] = type(exc).__name__
        record["error_detail"] = _bounded(exc)
        return record
    try:
        record["tls_completed"] = True
        record["verified"] = True
        record["tls_version"] = tls.version()
        cipher = tls.cipher()
        if cipher:
            record["cipher_name"], record["cipher_protocol"], record["cipher_bits"] = cipher
        record["negotiated_alpn"] = tls.selected_alpn_protocol()
        _record_certificate(record, tls.getpeercert(binary_form=True))
    except (OSError, ValueError) as exc:
        record["error_class"] = type(exc).__name__
        record["error_detail"] = _bounded(exc)
    finally:
        # Closing without writing is what keeps `application_bytes_sent` at 0.
        try:
            tls.close()
        except OSError:
            pass
    return record


def probe(candidate_ip: object, *, port: int = AUTHORIZED_PORT,
          timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Validate one literal public IPv4 candidate for the authorized hostname."""
    if not 0 < timeout <= MAX_TIMEOUT:
        raise UpstreamProbeError(f"timeout must be >0 and <= {MAX_TIMEOUT:g}")
    address = validate_production_target(AUTHORIZED_HOST, candidate_ip, port)
    record = _blank_record(AUTHORIZED_HOST, str(address), port)
    return _handshake(str(address), port, AUTHORIZED_HOST, _build_context(None), timeout, record)


def synthetic_probe(dial_host: str, port: int, server_hostname: str, ca_file: Path,
                    timeout: float = 5.0) -> dict:
    """Test-only entry point: loopback, high port, non-production hostname, explicit CA."""
    try:
        address = ipaddress.ip_address(str(dial_host))
    except ValueError as exc:
        raise UpstreamProbeError("synthetic probe requires a literal loopback address") from exc
    if not address.is_loopback:
        raise UpstreamProbeError("synthetic probe is loopback-only")
    if port < 1024:
        raise UpstreamProbeError("synthetic probe requires a high unprivileged port")
    if (server_hostname or "").strip().lower().rstrip(".") == AUTHORIZED_HOST:
        raise UpstreamProbeError("synthetic probe may not use the production hostname")
    if ca_file is None or not Path(ca_file).is_file():
        raise UpstreamProbeError("synthetic probe requires an explicit CA file")
    if not 0 < timeout <= MAX_TIMEOUT:
        raise UpstreamProbeError(f"timeout must be >0 and <= {MAX_TIMEOUT:g}")
    record = _blank_record(server_hostname, str(address), port)
    record["mode"] = "synthetic"
    return _handshake(
        str(address), port, server_hostname, _build_context(Path(ca_file)), timeout, record
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    # The hostname is a constant, not a flag: there is no CLI path to another host.
    parser.add_argument("--upstream-ip", required=True,
                        help=f"one literal public IPv4 candidate for {AUTHORIZED_HOST}")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()
    result = probe(args.upstream_ip, timeout=args.timeout)
    print(json.dumps(result, indent=2))
    return 0 if result["verified"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except UpstreamProbeError as exc:
        print(f"refusing: {exc}", file=sys.stderr)
        raise SystemExit(2)
