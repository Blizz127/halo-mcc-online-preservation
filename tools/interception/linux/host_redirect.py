"""Fail-closed planning and verification for one exact /etc/hosts redirect.

This module never changes /etc/hosts. It validates and records prior state,
emits reviewable inode-preserving operator commands, and verifies exact rollback.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exclusions import is_excluded  # noqa: E402

HOSTS_PATH = "/etc/hosts"
SENTINEL = "# P0C2D-REDIRECT (temporary; exact rollback required)"
OBSERVER_LOOPBACK = "127.0.0.77"
AUTHORIZED_HOST = "settings.svc.halowaypoint.com"
IDENTITY_HOSTS = (
    "login.live.com",
    "login.microsoftonline.com",
    "user.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "sisu.xboxlive.com",
    "title.mgt.xboxlive.com",
)
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,63}$")
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class RedirectSafetyError(ValueError):
    pass


def _path_has_symlink(path: Path) -> bool:
    absolute = Path(path).absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            return True
    return False


def _normalise(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def validate_target(selected_host: str, requested_host: str) -> None:
    req, selected = _normalise(requested_host), _normalise(selected_host)
    if not req:
        raise RedirectSafetyError("empty host")
    if "*" in req or req.startswith("."):
        raise RedirectSafetyError(f"wildcard or suffix redirect refused: {requested_host!r}")
    if not _HOSTNAME_RE.fullmatch(req):
        raise RedirectSafetyError(f"not a valid single hostname: {requested_host!r}")
    if is_excluded(req):
        raise RedirectSafetyError(f"host is on the exclusion denylist: {req}")
    if req != selected:
        raise RedirectSafetyError(f"requested host {req!r} is not selected host {selected!r}")


def _validate_contract(selected_host: str, address: str) -> None:
    validate_target(AUTHORIZED_HOST, selected_host)
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise RedirectSafetyError("observer address must be numeric") from exc
    if not isinstance(parsed, ipaddress.IPv4Address) or str(parsed) != OBSERVER_LOOPBACK:
        raise RedirectSafetyError(f"observer address must be exactly {OBSERVER_LOOPBACK}")


def read_our_entries(hosts_path: Path = Path(HOSTS_PATH)) -> list[str]:
    try:
        text = Path(hosts_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [line for line in text.splitlines() if SENTINEL in line]


def is_installed(selected_host: str, hosts_path: Path = Path(HOSTS_PATH)) -> bool:
    selected = _normalise(selected_host)
    return any(
        selected in line.lower().split("#", 1)[0].split()
        for line in read_our_entries(hosts_path)
    )


def install_commands(selected_host: str, address: str = OBSERVER_LOOPBACK,
                     hosts_path: Path = Path(HOSTS_PATH),
                     state_path: Path | None = None) -> list[str]:
    """Return one append-only command only after exact prior state was recorded."""
    _validate_contract(selected_host, address)
    if state_path is None:
        raise RedirectSafetyError("an exact prior-state record is required before installation")
    prior = verify_rollback(state_path, hosts_path)
    if not prior["verified"]:
        raise RedirectSafetyError("hosts file no longer matches the recorded prior state")
    try:
        lines = Path(hosts_path).read_text(encoding="utf-8", errors="strict").splitlines()
    except OSError as exc:
        raise RedirectSafetyError(f"cannot read hosts file: {exc}") from exc
    selected = _normalise(selected_host)
    if any(SENTINEL in line or selected in line.lower().split("#", 1)[0].split() for line in lines):
        raise RedirectSafetyError("selected host or sentinel already exists; refusing duplicate")
    record, _expected = _load_prior_state(state_path)
    entry = f"{address} {selected} {SENTINEL}"
    if record["authorized_line"] != entry:
        raise RedirectSafetyError("recorded authorized line does not match requested installation")
    if _expected and not _expected.endswith(b"\n"):
        raise RedirectSafetyError("hosts file must end with a newline before append-only installation")
    guard = (
        f"test \"$(stat -c '%i' -- {HOSTS_PATH})\" = {record['inode']!r} && "
        f"test \"$(sha256sum -- {HOSTS_PATH} | cut -d ' ' -f1)\" = {record['sha256']!r}"
    )
    return [f"{guard} && printf '%s\\n' {entry!r} | sudo tee -a {HOSTS_PATH} >/dev/null"]


def rollback_commands(state_path: Path, payload_path: Path) -> list[str]:
    """Return an inode-preserving exact-line removal after validating live state."""
    record, expected = _load_prior_state(state_path)
    hosts_path = Path(record["hosts_path"])
    cleaned, current_hash = _validated_cleaned_contents(record, expected, hosts_path)
    payload_path = Path(payload_path)
    if payload_path.is_symlink() or payload_path.read_bytes() != cleaned:
        raise RedirectSafetyError("rollback payload does not match validated exact-line removal")
    source = shlex.quote(str(payload_path.resolve(strict=True)))
    inode_guard = f"test \"$(stat -c '%i' -- {HOSTS_PATH})\" = {record['inode']!r}"
    hash_guard = (
        f"test \"$(sha256sum -- {HOSTS_PATH} | cut -d ' ' -f1)\" = {current_hash!r}"
    )
    return [
        f"{inode_guard} && {hash_guard} && "
        f"sudo cp --no-preserve=mode,ownership -- {source} {HOSTS_PATH}"
    ]


def emergency_rollback_command(record: dict) -> str:
    """Emit an inode-preserving command that removes only one exact project line."""
    encoded = base64.b64encode((record["authorized_line"] + "\n").encode("utf-8")).decode()
    script = f"""import base64, os
path = {HOSTS_PATH!r}
line = base64.b64decode({encoded!r})
read_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    before = os.fstat(read_fd)
    data = os.read(read_fd, before.st_size + 1)
finally:
    os.close(read_fd)
parts = data.splitlines(keepends=True)
if parts.count(line) != 1:
    raise SystemExit('refusing: exact authorized line count is not one')
cleaned = b''.join(part for part in parts if part != line)
write_fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
try:
    current = os.fstat(write_fd)
    if current.st_ino != before.st_ino or current.st_size != before.st_size:
        raise SystemExit('refusing: hosts file changed before emergency removal')
    os.ftruncate(write_fd, 0)
    pending = memoryview(cleaned)
    while pending:
        written = os.write(write_fd, pending)
        if written <= 0:
            raise SystemExit('refusing: emergency write did not make progress')
        pending = pending[written:]
    os.fsync(write_fd)
finally:
    os.close(write_fd)
"""
    return f"sudo python3 -c {shlex.quote(script)}"


def emergency_manual_removal_instruction(record: dict) -> str:
    return (
        "Do not restore a saved whole-file copy. The emergency command removes exactly one "
        f"authorized line and preserves all other bytes: {emergency_rollback_command(record)}"
    )


def _rollback_refusal(message: str, record: dict) -> RedirectSafetyError:
    return RedirectSafetyError(f"{message}. {emergency_manual_removal_instruction(record)}")


def _validated_cleaned_contents(record: dict, expected: bytes,
                                hosts_path: Path) -> tuple[bytes, str]:
    if hosts_path.is_symlink():
        raise _rollback_refusal("hosts path became a symlink", record)
    try:
        current = hosts_path.read_bytes()
        info = hosts_path.stat()
    except OSError as exc:
        raise _rollback_refusal(f"cannot read current hosts contents ({type(exc).__name__})", record)
    if info.st_ino != record["inode"]:
        raise _rollback_refusal("hosts inode changed", record)
    authorized = (record["authorized_line"] + "\n").encode("utf-8")
    lines = current.splitlines(keepends=True)
    exact_indices = [index for index, line in enumerate(lines) if line == authorized]
    sentinel_lines = [line for line in lines if record["sentinel"].encode("utf-8") in line]
    if len(exact_indices) != 1 or len(sentinel_lines) != 1:
        raise _rollback_refusal(
            "rollback requires exactly one exact authorized project line", record
        )
    cleaned = b"".join(line for index, line in enumerate(lines) if index != exact_indices[0])
    if cleaned != expected:
        raise _rollback_refusal("unrelated concurrent hosts-file changes detected", record)
    return cleaned, hashlib.sha256(current).hexdigest()


def resolve_family(host: str, family: int) -> list[str]:
    try:
        records = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
    except (OSError, socket.gaierror):
        return []
    return sorted({record[4][0] for record in records})


def resolve(host: str) -> list[str]:
    return resolve_family(host, socket.AF_INET)


def _identity_addresses_safe(addresses: list[str], observer: str) -> bool:
    if not addresses:
        return False
    for value in addresses:
        parsed = ipaddress.ip_address(value)
        if (
            str(parsed) == observer
            or parsed.is_loopback
            or parsed.is_unspecified
            or parsed.is_link_local
        ):
            return False
    return True


def verify_scope(selected_host: str, address: str,
                 identity_hosts: list[str] | tuple[str, ...] = IDENTITY_HOSTS) -> dict:
    """Require exact IPv4 redirect, no selected-host IPv6, and six safe identity resolutions."""
    _validate_contract(selected_host, address)
    if tuple(identity_hosts) != IDENTITY_HOSTS:
        raise RedirectSafetyError("all six authorized identity hosts are required")
    selected_v4 = resolve_family(selected_host, socket.AF_INET)
    selected_v6 = resolve_family(selected_host, socket.AF_INET6)
    report = {
        "selected_host": _normalise(selected_host),
        "selected_ipv4": selected_v4,
        "selected_ipv6": selected_v6,
        "selected_resolves_to": selected_v4 + selected_v6,
        "selected_points_at_observer": selected_v4 == [address] and not selected_v6,
        "sentinel_lines_present": read_our_entries(),
        "identity_hosts": {},
        "identity_hosts_unaffected": True,
        "all_checks_pass": False,
    }
    for host in identity_hosts:
        ipv4 = resolve_family(host, socket.AF_INET)
        ipv6 = resolve_family(host, socket.AF_INET6)
        addresses = ipv4 + ipv6
        safe = _identity_addresses_safe(addresses, address)
        report["identity_hosts"][host] = {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "redirected_to_observer": address in addresses,
            "safe": safe,
        }
        if not safe:
            report["identity_hosts_unaffected"] = False
    report["all_checks_pass"] = (
        report["selected_points_at_observer"]
        and report["identity_hosts_unaffected"]
        and len(report["sentinel_lines_present"]) == 1
    )
    return report


def record_prior_state(state_path: Path, hosts_path: Path = Path(HOSTS_PATH),
                       selected_host: str = AUTHORIZED_HOST,
                       address: str = OBSERVER_LOOPBACK) -> dict:
    """Persist exact original bytes, hash, mode and inode in a mode-0600 state file."""
    _validate_contract(selected_host, address)
    selected = _normalise(selected_host)
    state_path, hosts_path = Path(state_path), Path(hosts_path)
    if state_path.exists() or state_path.is_symlink():
        raise RedirectSafetyError("state path already exists or is a symlink")
    try:
        state_path.resolve(strict=False).relative_to(REPOSITORY_ROOT)
    except ValueError:
        pass
    else:
        raise RedirectSafetyError("prior-state record must be outside the repository")
    if not state_path.parent.is_dir():
        raise RedirectSafetyError("prior-state parent directory does not exist")
    if _path_has_symlink(state_path.parent):
        raise RedirectSafetyError("prior-state path may not traverse a symlink")
    if hosts_path.is_symlink():
        raise RedirectSafetyError("hosts path is a symlink")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    fd = os.open(hosts_path, flags)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        data = stream.read()
        after = os.fstat(stream.fileno())
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise RedirectSafetyError("hosts file changed while prior state was recorded")
    record = {
        "format": "p0c2d0-hosts-prior-state-v1",
        "hosts_path": str(hosts_path.resolve(strict=True)),
        "inode": after.st_ino,
        "mode": after.st_mode & 0o777,
        "size": after.st_size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "authorized_line": f"{address} {selected} {SENTINEL}",
        "sentinel": SENTINEL,
        "selected_host": selected,
        "address": address,
        "bytes_base64": base64.b64encode(data).decode("ascii"),
    }
    fd = os.open(state_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    return record


def _load_prior_state(state_path: Path) -> tuple[dict, bytes]:
    state_path = Path(state_path)
    if _path_has_symlink(state_path):
        raise RedirectSafetyError("prior-state record may not be a symlink")
    try:
        record = json.loads(state_path.read_text(encoding="utf-8"))
        if record.get("format") != "p0c2d0-hosts-prior-state-v1":
            raise ValueError("unexpected format")
        expected = base64.b64decode(record["bytes_base64"], validate=True)
        if hashlib.sha256(expected).hexdigest() != record["sha256"]:
            raise ValueError("embedded bytes do not match recorded hash")
        if (
            not isinstance(record["inode"], int)
            or not isinstance(record["mode"], int)
            or not isinstance(record["size"], int)
            or record["size"] != len(expected)
        ):
            raise ValueError("invalid recorded metadata")
        if not isinstance(record["hosts_path"], str):
            raise ValueError("invalid recorded path")
        if (
            record["sentinel"] != SENTINEL
            or record["selected_host"] != AUTHORIZED_HOST
            or record["address"] != OBSERVER_LOOPBACK
            or record["authorized_line"]
            != f"{OBSERVER_LOOPBACK} {AUTHORIZED_HOST} {SENTINEL}"
        ):
            raise ValueError("recorded redirect contract does not match the authorized contract")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RedirectSafetyError(f"invalid prior-state record: {exc}") from exc
    return record, expected


def materialize_rollback(state_path: Path, payload_path: Path,
                         hosts_path: Path | None = None) -> dict:
    """Create cleaned bytes only after exact-line removal validates live contents."""
    record, expected = _load_prior_state(state_path)
    target = Path(hosts_path) if hosts_path is not None else Path(record["hosts_path"])
    if str(target.resolve(strict=True)) != record["hosts_path"]:
        raise RedirectSafetyError("rollback target differs from recorded hosts path")
    cleaned, _current_hash = _validated_cleaned_contents(record, expected, target)
    payload_path = Path(payload_path)
    if payload_path.exists() or payload_path.is_symlink():
        raise RedirectSafetyError("rollback payload path already exists or is a symlink")
    try:
        payload_path.resolve(strict=False).relative_to(REPOSITORY_ROOT)
    except ValueError:
        pass
    else:
        raise RedirectSafetyError("rollback payload must be outside the repository")
    if not payload_path.parent.is_dir():
        raise RedirectSafetyError("rollback payload parent directory does not exist")
    if _path_has_symlink(payload_path.parent):
        raise RedirectSafetyError("rollback payload path may not traverse a symlink")
    fd = os.open(payload_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(cleaned)
    return {
        "payload_path": str(payload_path.resolve(strict=True)),
        "sha256": record["sha256"],
        "bytes": len(cleaned),
        "mode": "0o600",
    }


def verify_rollback(state_path: Path, hosts_path: Path = Path(HOSTS_PATH)) -> dict:
    record, expected = _load_prior_state(state_path)
    if str(Path(hosts_path).resolve(strict=True)) != record["hosts_path"]:
        raise RedirectSafetyError("verification target differs from recorded hosts path")
    data, stat = Path(hosts_path).read_bytes(), Path(hosts_path).stat()
    exact = data == expected
    inode = stat.st_ino == record["inode"]
    sentinel_absent = record["sentinel"].encode("utf-8") not in data
    return {
        "exact_bytes_restored": exact,
        "sha256_matches": hashlib.sha256(data).hexdigest() == record["sha256"],
        "size_matches": len(data) == record["size"],
        "inode_preserved": inode,
        "project_sentinel_absent": sentinel_absent,
        "verified": exact and inode and sentinel_absent,
    }


def flush_dns_cache_command() -> str:
    return "resolvectl flush-caches"


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    record = sub.add_parser("record-prior-state")
    record.add_argument("--state", type=Path, required=True)
    install = sub.add_parser("install-commands")
    install.add_argument("selected_host")
    install.add_argument("--address", default=OBSERVER_LOOPBACK)
    install.add_argument("--state", type=Path, required=True)
    materialize = sub.add_parser("materialize-rollback")
    materialize.add_argument("--state", type=Path, required=True)
    materialize.add_argument("--output", type=Path, required=True)
    rollback = sub.add_parser("rollback-commands")
    rollback.add_argument("--state", type=Path, required=True)
    rollback.add_argument("--payload", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("selected_host")
    verify.add_argument("--address", default=OBSERVER_LOOPBACK)
    verify_rollback_parser = sub.add_parser("verify-rollback")
    verify_rollback_parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "record-prior-state":
        recorded = record_prior_state(args.state)
        print(json.dumps({key: value for key, value in recorded.items()
                          if key != "bytes_base64"}, indent=2))
    elif args.command == "install-commands":
        print(json.dumps({
            "commands": install_commands(
                args.selected_host, args.address, state_path=args.state
            )
        }, indent=2))
    elif args.command == "materialize-rollback":
        print(json.dumps(materialize_rollback(args.state, args.output), indent=2))
    elif args.command == "rollback-commands":
        print(json.dumps({"commands": rollback_commands(args.state, args.payload)}, indent=2))
    elif args.command == "verify-rollback":
        result = verify_rollback(args.state)
        print(json.dumps(result, indent=2))
        if not result["verified"]:
            raise SystemExit(2)
    else:
        result = verify_scope(args.selected_host, args.address)
        print(json.dumps(result, indent=2))
        if not result["all_checks_pass"]:
            raise SystemExit(2)
