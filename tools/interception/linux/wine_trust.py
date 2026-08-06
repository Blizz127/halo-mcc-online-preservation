"""Install / remove a test CA in a Proton-Wine prefix's own Root certificate store.

A Wine prefix keeps an independent Root store in its registry under
`HKLM\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\<SHA1>`,
populated from the host bundle when the prefix is created. Writing there is
**prefix-scoped and needs no administrative privileges**, which makes it the
least invasive way to grant trust for a test: it cannot affect the host, other
prefixes, or any other application, and it is removed by deleting one key.

Registry value format
---------------------
The `Blob` value is a serialized certificate-context property list, not bare
DER. Each element is `<DWORD propId><DWORD encodingType><DWORD length><data>`;
the certificate itself is property 32 (`CERT_CERT_PROP_ID`) with encoding 1
(`X509_ASN_ENCODING`). The key name is the certificate's SHA-1 thumbprint in
uppercase hex.

Safety
------
`install` refuses any certificate that is not a CA, and refuses one whose
validity exceeds a short bound, so a long-lived interception root cannot be
placed into a prefix by this tool. `remove` is exact-match on thumbprint and
reports whether the key was actually gone afterwards, so rollback can be
*verified* rather than assumed.
"""

from __future__ import annotations

import datetime
import struct
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

CERT_CERT_PROP_ID = 32
X509_ASN_ENCODING = 1
ROOT_KEY = r"HKLM\Software\Microsoft\SystemCertificates\Root\Certificates"
MAX_VALIDITY_DAYS = 30


def thumbprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA1()).hex().upper()


def serialize_blob(der: bytes) -> bytes:
    return struct.pack("<III", CERT_CERT_PROP_ID, X509_ASN_ENCODING, len(der)) + der


def _run_wine(prefix: Path, proton_wine: Path, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    import os

    env = dict(os.environ)
    env["WINEPREFIX"] = str(prefix)
    env["WINEDEBUG"] = "-all"
    return subprocess.run(
        [str(proton_wine), *args], capture_output=True, text=True, timeout=timeout, check=False, env=env
    )


def install(cert_path: Path, prefix: Path, proton_wine: Path, scratch: Path) -> dict:
    der_pem = Path(cert_path).read_bytes()
    cert = x509.load_pem_x509_certificate(der_pem)

    basic = None
    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        pass
    if basic is None or not basic.ca:
        raise SystemExit("refusing: certificate is not a CA")

    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    if lifetime > datetime.timedelta(days=MAX_VALIDITY_DAYS):
        raise SystemExit(f"refusing: CA validity {lifetime.days}d exceeds {MAX_VALIDITY_DAYS}d bound")

    tp = thumbprint(cert)
    blob = serialize_blob(cert.public_bytes(serialization.Encoding.DER))

    # `reg add` rather than `regedit <file>`: regedit is a GUI application and
    # hangs instead of exiting when handed a file under Wine. reg.exe is a
    # console tool that imports and returns an exit code. Its REG_BINARY data is
    # one contiguous hex string with no separators.
    result = _run_wine(prefix, proton_wine, [
        "reg", "add", f"{ROOT_KEY}\\{tp}",
        "/v", "Blob", "/t", "REG_BINARY", "/d", blob.hex(), "/f",
    ])
    return {
        "action": "install",
        "thumbprint_sha1": tp,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(":", 1),
        "registry_key": f"{ROOT_KEY}\\{tp}",
        "blob_bytes": len(blob),
        "reg_exit_code": result.returncode,
        "stdout_tail": (result.stdout or "").strip().splitlines()[-2:] or None,
    }


def is_present(tp: str, prefix: Path, proton_wine: Path) -> bool:
    result = _run_wine(prefix, proton_wine, ["reg", "query", f"{ROOT_KEY}\\{tp}"])
    return result.returncode == 0 and tp.lower() in (result.stdout or "").lower()


def remove(tp: str, prefix: Path, proton_wine: Path) -> dict:
    result = _run_wine(prefix, proton_wine, ["reg", "delete", f"{ROOT_KEY}\\{tp}", "/f"])
    still_there = is_present(tp, prefix, proton_wine)
    return {
        "action": "remove",
        "thumbprint_sha1": tp,
        "reg_exit_code": result.returncode,
        "verified_absent": not still_there,
    }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "remove", "check"))
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--proton-wine", type=Path, required=True)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--thumbprint")
    parser.add_argument("--scratch", type=Path, default=Path("/tmp"))
    args = parser.parse_args()

    if args.action == "install":
        if not args.cert:
            raise SystemExit("--cert required")
        print(json.dumps(install(args.cert, args.prefix, args.proton_wine, args.scratch), indent=2))
    else:
        tp = args.thumbprint
        if not tp and args.cert:
            tp = thumbprint(x509.load_pem_x509_certificate(Path(args.cert).read_bytes()))
        if not tp:
            raise SystemExit("--thumbprint or --cert required")
        if args.action == "check":
            print(json.dumps({"thumbprint_sha1": tp,
                              "present": is_present(tp, args.prefix, args.proton_wine)}, indent=2))
        else:
            print(json.dumps(remove(tp, args.prefix, args.proton_wine), indent=2))
