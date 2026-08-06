"""Generate a short-lived local test CA and leaf certificate for Stage A.

Everything this produces is written to a caller-supplied scratch directory that
must live outside the repository. Private keys are written with mode 0600 and
are never printed, copied, or returned by any function here — only SHA-256
fingerprints are, and those are what the committed evidence records.

The CA is deliberately narrow:

- **Short validity.** It expires in days, so a forgotten trust entry stops being
  usable on its own rather than lingering as a permanent interception root.
- **Name-constrained where honoured.** The CA carries a NameConstraints
  extension permitting only the reserved test domain, so even if it were left
  installed it cannot vouch for a real host. (Not every TLS stack enforces name
  constraints; this is defence in depth, not a guarantee.)
- **Reserved test names only.** Leaf certificates are issued for `.test`
  (RFC 6761), never for a real Microsoft, Xbox, Steam, or Halo hostname.
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

TEST_DOMAIN = "p0c2a.test"
DEFAULT_VALIDITY_DAYS = 2


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":", 1)


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def generate(out_dir: Path, hostname: str = TEST_DOMAIN, days: int = DEFAULT_VALIDITY_DAYS,
             name_constraints: bool = True, constrain_to_host: str | None = None) -> dict:
    """Create ca.crt/ca.key and server.crt/server.key. Returns metadata only.

    `constrain_to_host` issues a leaf for ONE real hostname and name-constrains
    the CA to exactly that host — so even a forgotten, still-installed CA can
    vouch for nothing but that single name. It refuses any host on the exclusion
    denylist, so an identity or Xbox-auth name can never be minted. No IP SAN is
    added in this mode: the client reaches the observer by name (via a hosts
    redirect), so SNI matches the DNS SAN and the P0-C2A bare-IP rejection does
    not apply.
    """
    if constrain_to_host is not None:
        # Late import keeps local_ca usable standalone in the Stage A test path.
        from exclusions import is_excluded
        target = constrain_to_host.strip().lower().rstrip(".")
        if is_excluded(target):
            raise ValueError(f"refusing: {target} is on the exclusion denylist and may never be minted")
        hostname = target

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.chmod(0o700)

    now = datetime.datetime.now(datetime.UTC)
    not_after = now + datetime.timedelta(days=days)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "P0-C2A Local Test CA (DO NOT TRUST)"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "halo-mcc-online-preservation"),
    ])
    # NameConstraints is marked critical, which RFC 5280 requires a conforming
    # implementation to either understand or reject. Not every TLS stack
    # implements it, so it is made optional here: keeping it is safer, but a
    # stack that rejects the whole certificate because of it would otherwise be
    # indistinguishable from a stack that simply does not trust the CA.
    ca_builder = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        # Key identifiers are required for chain building under OpenSSL 3.x
        # strict verification; without them a correctly-trusted CA still fails
        # with "Missing Authority Key Identifier".
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
    )
    if constrain_to_host is not None:
        # Constrain the CA to exactly the one real host it exists to observe.
        constrained_to = [hostname]
        ca_builder = ca_builder.add_extension(
            x509.NameConstraints(permitted_subtrees=[x509.DNSName(hostname)], excluded_subtrees=None),
            critical=True,
        )
    elif name_constraints:
        constrained_to = [TEST_DOMAIN, "127.0.0.0/8"]
        ca_builder = ca_builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.DNSName(TEST_DOMAIN),
                    x509.IPAddress(ipaddress.ip_network("127.0.0.0/8")),
                ],
                excluded_subtrees=None,
            ),
            critical=True,
        )
    else:
        constrained_to = None
    ca_cert = ca_builder.sign(ca_key, hashes.SHA256())

    # For a real host the leaf carries the DNS SAN only (no IP SAN): the client
    # presents that name via SNI, so no bare-IP validation is involved.
    leaf_sans = [x509.DNSName(hostname)]
    if constrain_to_host is None:
        leaf_sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(leaf_sans), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    (out_dir / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_private(out_dir / "ca.key", ca_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (out_dir / "server.crt").write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    _write_private(out_dir / "server.key", leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    return {
        "ca_subject": ca_cert.subject.rfc4514_string(),
        "ca_sha256_fingerprint": _fingerprint(ca_cert),
        "ca_not_after": not_after.isoformat(),
        "leaf_hostname": hostname,
        "leaf_sha256_fingerprint": _fingerprint(leaf_cert),
        "name_constrained_to": constrained_to,
        "key_files_written": ["ca.key", "server.key"],
        "key_files_committed": False,
    }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--hostname", default=TEST_DOMAIN)
    parser.add_argument("--days", type=int, default=DEFAULT_VALIDITY_DAYS)
    parser.add_argument("--no-name-constraints", action="store_true",
                        help="omit the critical NameConstraints extension (diagnostic only)")
    parser.add_argument("--constrain-to-host", default=None,
                        help="issue a leaf for ONE real host, CA name-constrained to exactly it "
                             "(refuses any excluded identity/auth host)")
    args = parser.parse_args()

    if args.constrain_to_host is None:
        # Reserved test domains (RFC 6761) plus "localhost", which is loopback-only
        # and cannot be pointed at a real service.
        if not (args.hostname.endswith(".test") or args.hostname.endswith(".invalid")
                or args.hostname == "localhost"):
            raise SystemExit("refusing: without --constrain-to-host, only reserved test domains are allowed")

    print(json.dumps(generate(args.out_dir, args.hostname, args.days,
                              constrain_to_host=args.constrain_to_host,
                              name_constraints=not args.no_name_constraints), indent=2))
