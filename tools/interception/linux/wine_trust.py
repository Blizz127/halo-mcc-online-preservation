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
import re
import struct
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

CERT_CERT_PROP_ID = 32
X509_ASN_ENCODING = 1
ROOT_KEY = r"HKLM\Software\Microsoft\SystemCertificates\Root\Certificates"
MAX_VALIDITY_DAYS = 2


def normalize_thumbprint(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9A-Fa-f]{40}", value) is None:
        raise ValueError("thumbprint must be exactly 40 hexadecimal characters")
    return value.upper()


def thumbprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA1()).hex().upper()


def serialize_blob(der: bytes) -> bytes:
    return struct.pack("<III", CERT_CERT_PROP_ID, X509_ASN_ENCODING, len(der)) + der


def _run_wine(
    prefix: Path, proton_wine: Path, args: list[str], timeout: int = 120
) -> subprocess.CompletedProcess:
    import os

    env = dict(os.environ)
    env["WINEPREFIX"] = str(prefix)
    env["WINEDEBUG"] = "-all"
    return subprocess.run(
        [str(proton_wine), *args], capture_output=True, text=True,
        timeout=timeout, check=False, env=env,
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
        raise SystemExit(
            f"refusing: CA validity {lifetime.days}d exceeds {MAX_VALIDITY_DAYS}d bound"
        )

    tp = normalize_thumbprint(thumbprint(cert))
    blob = serialize_blob(cert.public_bytes(serialization.Encoding.DER))

    # `reg add` rather than `regedit <file>`: regedit is a GUI application and
    # hangs instead of exiting when handed a file under Wine. reg.exe is a
    # console tool that imports and returns an exit code. Its REG_BINARY data is
    # one contiguous hex string with no separators.
    result = _run_wine(prefix, proton_wine, [
        "reg", "add", f"{ROOT_KEY}\\{tp}",
        "/v", "Blob", "/t", "REG_BINARY", "/d", blob.hex(), "/f",
    ])
    if result.returncode != 0:
        raise SystemExit(f"CA install failed closed: reg add exited {result.returncode}")
    query = query_presence(tp, prefix, proton_wine)
    if query["status"] != "present":
        raise SystemExit("CA install failed closed: exact thumbprint was not present after reg add")
    return {
        "action": "install",
        "thumbprint_sha1": tp,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(":", 1),
        "registry_key": f"{ROOT_KEY}\\{tp}",
        "blob_bytes": len(blob),
        "reg_exit_code": result.returncode,
        "verified_present": True,
        "verified_exact_thumbprint_present": True,
        "query_status": query["status"],
        "query_exit_code": query["returncode"],
        "stdout_tail": (result.stdout or "").strip().splitlines()[-2:] or None,
    }


def query_presence(tp: str, prefix: Path, proton_wine: Path) -> dict:
    normalized = normalize_thumbprint(tp)
    result = _run_wine(prefix, proton_wine, ["reg", "query", f"{ROOT_KEY}\\{tp}"])
    if result.returncode != 0:
        combined = f"{result.stdout or ''}\n{result.stderr or ''}".casefold()
        absent = result.returncode == 1 and (
            "unable to find" in combined or "not found" in combined
        )
        return {
            "status": "absent" if absent else "error",
            "returncode": result.returncode,
        }
    lines = [line.strip() for line in (result.stdout or "").splitlines()]
    expected_suffix = (
        rf"\software\microsoft\systemcertificates\root\certificates\{normalized}".lower()
    )
    exact_key = any(
        line.lower().startswith("hkey_") and line.lower().endswith(expected_suffix)
        for line in lines
    )
    blob_present = any(
        re.match(r"^Blob\s+REG_BINARY(?:\s|$)", line, re.IGNORECASE)
        for line in lines
    )
    return {
        "status": "present" if exact_key and blob_present else "error",
        "returncode": result.returncode,
    }


def is_present(tp: str, prefix: Path, proton_wine: Path) -> bool:
    try:
        return query_presence(tp, prefix, proton_wine)["status"] == "present"
    except ValueError:
        return False


def presence_read_only(tp: str, prefix: Path) -> dict:
    """Inspect Wine's text registry without starting Wine or mutating the prefix."""
    try:
        normalized = normalize_thumbprint(tp)
    except ValueError:
        return {"status": "error", "reason": "invalid_thumbprint"}
    registry = Path(prefix) / "system.reg"
    if registry.is_symlink():
        return {"status": "error", "reason": "registry_symlink"}
    try:
        lines = registry.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError):
        return {"status": "error", "reason": "registry_read_failed"}
    expected = (
        "[Software\\\\Microsoft\\\\SystemCertificates\\\\Root\\\\Certificates"
        f"\\\\{normalized}]"
    )
    in_exact_key = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            header = stripped.split("]", 1)[0] + "]" if "]" in stripped else stripped
            in_exact_key = header.casefold() == expected.casefold()
            continue
        if in_exact_key and stripped.casefold().startswith('"blob"=hex:'):
            return {"status": "present"}
    return {"status": "absent"}


def is_present_read_only(tp: str, prefix: Path) -> bool:
    return presence_read_only(tp, prefix)["status"] == "present"


def remove(tp: str, prefix: Path, proton_wine: Path) -> dict:
    normalized = normalize_thumbprint(tp)
    result = _run_wine(
        prefix, proton_wine, ["reg", "delete", f"{ROOT_KEY}\\{normalized}", "/f"]
    )
    if result.returncode != 0:
        raise SystemExit(f"CA removal failed closed: reg delete exited {result.returncode}")
    query = query_presence(normalized, prefix, proton_wine)
    if query["status"] == "error":
        raise SystemExit("CA removal failed closed: post-delete exact-thumbprint query failed")
    if query["status"] == "present":
        raise SystemExit("CA removal failed closed: exact thumbprint remains after reg delete")
    return {
        "action": "remove",
        "thumbprint_sha1": normalized,
        "delete_exit_code": result.returncode,
        "query_exit_code": query["returncode"],
        "query_status": query["status"],
        "verified_absent": True,
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
