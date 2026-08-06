"""Read-only, fail-closed preflight for the P0-C2D live experiment.

The checker performs only file reads, process/socket-table inspection, DNS
resolution, and Git queries with optional locks disabled. It never binds a
socket, starts Wine, changes a store, edits hosts, or terminates a process.

**Stages.** The expected repository relationship and the certificate contract
both depend on which live rung is being gated, so both are supplied explicitly
rather than inferred:

- ``blind-relay`` forwards raw TLS bytes and terminates nothing. It requires no
  CA, certificate, key, or Wine prefix, so no certificate file is read and no
  Wine registry is inspected. Supplying certificate material is itself a
  failure, because it signals the operator is running the wrong contract.
- ``tls-observer`` terminates TLS and therefore requires its certificate inputs,
  plus the optional Wine CA-absence check when a prefix is supplied.

The Git expectation is likewise explicit: ahead and behind are computed
separately and compared to supplied values, so a pushed-and-synchronized tip
(0/0) and a local-only review state (1/0) are both expressible and neither is
assumed. No commit hash is hardcoded.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, str(Path(__file__).resolve().parent))
import host_redirect  # noqa: E402
import prelaunch_relay  # noqa: E402
import wine_trust  # noqa: E402

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
STAGE_BLIND_RELAY = "blind-relay"
STAGE_TLS_OBSERVER = "tls-observer"
STAGES = (STAGE_BLIND_RELAY, STAGE_TLS_OBSERVER)
DEFAULT_REMOTE_REF = "origin/main"
CA_ARGUMENT_NAMES = ("cert", "key", "prefix", "proton_wine", "ca_thumbprint")
PROXY_VARIABLES = (
    "http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"
)
NO_PROXY_VARIABLES = ("no_proxy", "NO_PROXY")
PROJECT_SENTINELS = ("P0C2C-REDIRECT", "P0C2D-REDIRECT")
PROCESS_MARKERS = {
    "relay": ("prelaunch_relay.py",),
    "observer": ("tls_observer.py",),
    "metadata_proxy": ("metadata_proxy.py",),
    "reverse_proxy": ("reverse_proxy.py",),
    "packet_capture": ("tcpdump", "dumpcap", "tshark", "wireshark"),
    "mcc": ("mcc-win64-shipping", "mcclauncher.exe"),
}


def _outside_repository(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT)
    except ValueError:
        return True
    return False


def _default_command(args: list[str]) -> subprocess.CompletedProcess:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(
        args, cwd=REPOSITORY_ROOT, capture_output=True, text=True,
        timeout=10, check=False, env=environment,
    )


def _default_processes() -> list[tuple[int, str]]:
    rows = []
    for process in Path("/proc").glob("[0-9]*"):
        pid = int(process.name)
        if pid == os.getpid():
            continue
        try:
            command = (process / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8", errors="replace"
            ).casefold()
            comm = (process / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        rows.append((pid, f"{comm} {command}".casefold()))
    return rows


def _default_listener_in_use(address: str, port: int) -> bool:
    target_address = socket.inet_aton(address)[::-1].hex().upper()
    target_port = f"{port:04X}"
    try:
        lines = Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return True
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == f"{target_address}:{target_port}" and fields[3] == "0A":
            return True
    return False


def _default_resolve(host: str, family: int) -> list[str]:
    return host_redirect.resolve_family(host, family)


def _default_read_hosts() -> bytes:
    return Path(host_redirect.HOSTS_PATH).read_bytes()


def _dependencies(overrides: dict | None) -> dict:
    result = {
        "command": _default_command,
        "processes": _default_processes,
        "listener_in_use": _default_listener_in_use,
        "resolve": _default_resolve,
        "read_hosts": _default_read_hosts,
        "environment": dict(os.environ),
        "tool_exists": lambda name: shutil.which(name) is not None,
        "wine_presence": wine_trust.presence_read_only,
    }
    if overrides:
        result.update(overrides)
    return result


def _parse_ahead_behind(text: str | None) -> tuple[int | None, int | None]:
    """Split ``rev-list --left-right --count <remote>...HEAD`` into (ahead, behind).

    The left count is commits reachable only from the remote ref (behind); the
    right count is commits reachable only from HEAD (ahead). Anything that is
    not exactly two non-negative integers is treated as malformed.
    """
    fields = (text or "").split()
    if len(fields) != 2:
        return None, None
    try:
        behind, ahead = int(fields[0]), int(fields[1])
    except ValueError:
        return None, None
    if behind < 0 or ahead < 0:
        return None, None
    return ahead, behind


def _run_git_checks(expected_branch: str, expected_head: str, expected_remote_tip: str,
                    expected_ahead: int, expected_behind: int, command,
                    expected_parent: str | None = None,
                    remote_ref: str = DEFAULT_REMOTE_REF) -> dict:
    queries = {
        "branch": ["git", "branch", "--show-current"],
        "head": ["git", "rev-parse", "HEAD"],
        "remote_tip": ["git", "rev-parse", remote_ref],
        "status": ["git", "status", "--porcelain", "--untracked-files=normal"],
        "ahead_behind": ["git", "rev-list", "--left-right", "--count", f"{remote_ref}...HEAD"],
    }
    if expected_parent is not None:
        queries["parent"] = ["git", "rev-parse", "HEAD^"]
    values: dict[str, str | None] = {}
    errors = []
    for name, args in queries.items():
        try:
            result = command(args)
        except (OSError, subprocess.SubprocessError):
            errors.append(name)
            values[name] = None
            continue
        if result.returncode != 0:
            errors.append(name)
            values[name] = None
        else:
            values[name] = result.stdout.strip()
    ahead, behind = _parse_ahead_behind(values.get("ahead_behind"))
    if ahead is None or behind is None:
        errors.append("ahead_behind_malformed")
    matches = {
        "branch": values.get("branch") == expected_branch,
        "head": values.get("head") == expected_head,
        "remote_tip": values.get("remote_tip") == expected_remote_tip,
        "clean": values.get("status") == "",
        "ahead": ahead is not None and ahead == expected_ahead,
        "behind": behind is not None and behind == expected_behind,
    }
    expected = {
        "branch": expected_branch, "head": expected_head,
        "remote_tip": expected_remote_tip, "ahead": expected_ahead,
        "behind": expected_behind, "clean": True,
    }
    actual = {
        "branch": values.get("branch"), "head": values.get("head"),
        "remote_tip": values.get("remote_tip"), "ahead": ahead, "behind": behind,
        "clean": values.get("status") == "",
    }
    if expected_parent is not None:
        matches["parent"] = values.get("parent") == expected_parent
        expected["parent"] = expected_parent
        actual["parent"] = values.get("parent")
    return {
        "pass": not errors and all(matches.values()), "matches": matches,
        "errors": errors, "expected": expected, "actual": actual, "remote_ref": remote_ref,
    }


def _certificate_check(cert_path: Path, key_path: Path) -> dict:
    try:
        ca_path = Path(cert_path).with_name("ca.crt")
        if not all(path.is_file() for path in (Path(cert_path), Path(key_path), ca_path)):
            raise ValueError("certificate inputs must be regular files")
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
        private_key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
        key_mode = Path(key_path).stat().st_mode & 0o777
        lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
        ca_lifetime = ca.not_valid_after_utc - ca.not_valid_before_utc
        dns = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        ca_basic = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        constraints = ca.extensions.get_extension_for_class(x509.NameConstraints)
        permitted = [name.value for name in constraints.value.permitted_subtrees or []]
        excluded = [name.value for name in constraints.value.excluded_subtrees or []]
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
        key_matches = private_key.public_key().public_bytes(
            serialization.Encoding.DER, public_format
        ) == cert.public_key().public_bytes(serialization.Encoding.DER, public_format)
        ca.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        now = datetime.datetime.now(datetime.UTC)
        passed = (
            dns == [prelaunch_relay.AUTHORIZED_HOST]
            and lifetime <= datetime.timedelta(days=2)
            and ca_lifetime <= datetime.timedelta(days=2)
            and cert.not_valid_before_utc <= now < cert.not_valid_after_utc
            and ca.not_valid_before_utc <= now < ca.not_valid_after_utc
            and ca_basic.ca and ca_basic.path_length == 0 and constraints.critical
            and permitted == [prelaunch_relay.AUTHORIZED_HOST]
            and excluded == [f".{prelaunch_relay.AUTHORIZED_HOST}"]
            and cert.issuer == ca.subject and key_matches and key_mode == 0o600
            and _outside_repository(Path(cert_path)) and _outside_repository(Path(key_path))
            and not prelaunch_relay._path_has_symlink(Path(cert_path))
            and not prelaunch_relay._path_has_symlink(Path(key_path))
        )
        return {"pass": passed, "leaf_dns_names": dns, "key_mode": oct(key_mode)}
    except (InvalidSignature, OSError, TypeError, ValueError, x509.ExtensionNotFound) as exc:
        return {"pass": False, "reason": type(exc).__name__}


def _hosts_check(read_hosts, resolve) -> dict:
    try:
        data = read_hosts()
        text = data.decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return {"pass": False, "reason": "hosts_read_failed"}
    sentinel_present = any(marker in text for marker in PROJECT_SENTINELS)
    selected = host_redirect.AUTHORIZED_HOST
    manual_lines = []
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and selected in (field.casefold().rstrip(".") for field in fields[1:]):
            manual_lines.append(line)
    selected_v4 = resolve(selected, socket.AF_INET)
    selected_v6 = resolve(selected, socket.AF_INET6)
    addresses = selected_v4 + selected_v6
    normal_resolution = bool(addresses) and all(ipaddress.ip_address(value).is_global for value in addresses)
    return {
        "pass": not sentinel_present and not manual_lines and normal_resolution,
        "sentinel_present": sentinel_present,
        "manual_selected_host_entry": bool(manual_lines),
        "selected_ipv4": selected_v4,
        "selected_ipv6": selected_v6,
        "selected_resolves_normally": normal_resolution,
    }


def _identity_check(resolve) -> dict:
    reports = {}
    for host in host_redirect.IDENTITY_HOSTS:
        ipv4 = resolve(host, socket.AF_INET)
        ipv6 = resolve(host, socket.AF_INET6)
        values = ipv4 + ipv6
        safe = bool(values)
        for value in values:
            parsed = ipaddress.ip_address(value)
            if (
                str(parsed) == host_redirect.OBSERVER_LOOPBACK
                or parsed.is_loopback or parsed.is_private or parsed.is_link_local
                or parsed.is_unspecified or not parsed.is_global
            ):
                safe = False
        reports[host] = {"ipv4": ipv4, "ipv6": ipv6, "safe": safe}
    return {"pass": all(item["safe"] for item in reports.values()), "hosts": reports}


def _path_check(scratch_path: Path, output_paths: list[Path]) -> dict:
    paths = [Path(path) for path in output_paths]
    scratch = Path(scratch_path)
    reasons = []
    if not scratch.is_dir() or not _outside_repository(scratch) or prelaunch_relay._path_has_symlink(scratch):
        reasons.append("scratch path must be an existing non-symlink directory outside repository")
    for path in paths:
        if (
            not _outside_repository(path)
            or prelaunch_relay._path_has_symlink(path.parent)
            or not path.parent.is_dir()
            or path.exists() or path.is_symlink()
        ):
            reasons.append("an output path is existing, unsafe, symlinked, or inside repository")
            break
    return {"pass": not reasons, "reasons": reasons}


def run_preflight(*, stage: str, upstream_ip: str,
                  pid_file: Path, ready_file: Path, log_path: Path,
                  expected_branch: str, expected_head: str, expected_remote_tip: str,
                  scratch_path: Path, expected_ahead: int = 0, expected_behind: int = 0,
                  expected_parent: str | None = None, remote_ref: str = DEFAULT_REMOTE_REF,
                  cert_path: Path | None = None, key_path: Path | None = None,
                  prefix: Path | None = None, proton_wine: Path | None = None,
                  ca_thumbprint: str | None = None, require_steam_closed: bool = True,
                  required_tools: tuple[str, ...] = ("git", "python3"),
                  dependencies: dict | None = None) -> dict:
    if stage not in STAGES:
        raise ValueError(f"stage must be one of {STAGES}; it is never inferred")
    deps = _dependencies(dependencies)
    checks: dict[str, dict] = {}

    checks["git"] = _run_git_checks(
        expected_branch, expected_head, expected_remote_tip,
        expected_ahead, expected_behind, deps["command"], expected_parent, remote_ref,
    )
    proxy_values = {
        name: bool(deps["environment"].get(name)) for name in PROXY_VARIABLES
    }
    checks["proxy_environment"] = {
        "pass": not any(proxy_values.values()), "active": proxy_values,
        "no_proxy_configured": {
            name: bool(deps["environment"].get(name)) for name in NO_PROXY_VARIABLES
        },
    }
    try:
        prelaunch_relay.validate_production_contract(
            prelaunch_relay.AUTHORIZED_BIND, prelaunch_relay.AUTHORIZED_HOST,
            upstream_ip, prelaunch_relay.AUTHORIZED_PORT,
        )
        checks["relay_contract"] = {"pass": True}
    except ValueError as exc:
        checks["relay_contract"] = {"pass": False, "reason": str(exc)}

    checks["listener"] = {
        "pass": not deps["listener_in_use"](
            prelaunch_relay.AUTHORIZED_BIND, prelaunch_relay.AUTHORIZED_PORT
        ),
        "bind": f"{prelaunch_relay.AUTHORIZED_BIND}:{prelaunch_relay.AUTHORIZED_PORT}",
    }
    process_hits = {name: [] for name in PROCESS_MARKERS}
    steam = []
    for pid, command in deps["processes"]():
        for name, markers in PROCESS_MARKERS.items():
            if any(marker in command for marker in markers):
                process_hits[name].append(pid)
        if "steam" in command:
            steam.append(pid)
    checks["processes"] = {
        "pass": not any(process_hits.values()) and (not require_steam_closed or not steam),
        "project_processes": process_hits, "steam_pids": sorted(set(steam)),
        "steam_required_closed": require_steam_closed,
    }
    checks["hosts"] = _hosts_check(deps["read_hosts"], deps["resolve"])
    checks["identity_hosts"] = _identity_check(deps["resolve"])
    checks["paths"] = _path_check(
        Path(scratch_path), [Path(pid_file), Path(ready_file), Path(log_path)]
    )

    tool_results = {name: bool(deps["tool_exists"](name)) for name in required_tools}
    if proton_wine is not None:
        tool_results[str(proton_wine)] = Path(proton_wine).is_file() and os.access(proton_wine, os.X_OK)
    checks["tools"] = {"pass": all(tool_results.values()), "available": tool_results}

    certificate_arguments = dict(zip(
        CA_ARGUMENT_NAMES, (cert_path, key_path, prefix, proton_wine, ca_thumbprint)
    ))
    supplied_names = sorted(name for name, value in certificate_arguments.items() if value is not None)
    if stage == STAGE_BLIND_RELAY:
        # A blind relay terminates nothing, so certificate material is not just
        # unnecessary — its presence means the operator is running the wrong
        # contract, and that is reported rather than ignored.
        checks["stage"] = {
            "pass": not supplied_names, "stage": stage,
            "certificate_material_required": False,
            "unexpected_arguments": supplied_names,
        }
        checks["certificate"] = {"pass": True, "status": "not_applicable_blind_relay"}
        checks["ca_absence"] = {"pass": True, "status": "not_applicable_blind_relay"}
    else:
        missing = [
            name for name, value in (("cert", cert_path), ("key", key_path)) if value is None
        ]
        checks["stage"] = {
            "pass": not missing, "stage": stage,
            "certificate_material_required": True,
            "missing_arguments": missing,
        }
        checks["certificate"] = (
            _certificate_check(Path(cert_path), Path(key_path)) if not missing
            else {"pass": False, "reason": "missing_certificate_inputs"}
        )
        supplied = (prefix is not None, proton_wine is not None, ca_thumbprint is not None)
        if any(supplied) and not all(supplied):
            checks["ca_absence"] = {
                "pass": False,
                "reason": "prefix, proton_wine, and ca_thumbprint are required together",
            }
        elif all(supplied):
            try:
                normalized = wine_trust.normalize_thumbprint(ca_thumbprint)
                if not Path(prefix).is_dir() or not _outside_repository(Path(prefix)):
                    raise ValueError("Wine prefix must be an existing directory outside repository")
                presence = deps["wine_presence"](normalized, Path(prefix))
                checks["ca_absence"] = {
                    "pass": presence["status"] == "absent", "status": presence["status"],
                    "inspection": "read-only system.reg parse; Wine was not started",
                }
            except (OSError, ValueError) as exc:
                checks["ca_absence"] = {"pass": False, "reason": type(exc).__name__}
        else:
            checks["ca_absence"] = {"pass": True, "status": "not_requested"}

    passed = all(item["pass"] for item in checks.values())
    return {"format": "p0c2d0r2-preflight-v3", "pass": passed, "stage": stage, "checks": checks}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=STAGES, required=True,
                        help="live contract being gated; never inferred from other arguments")
    parser.add_argument("--upstream-ip", required=True)
    parser.add_argument("--pid-file", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--expected-branch", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-remote-tip", required=True)
    parser.add_argument("--expected-ahead", type=int, default=0)
    parser.add_argument("--expected-behind", type=int, default=0)
    parser.add_argument("--expected-parent", default=None,
                        help="optional; checked only when supplied")
    parser.add_argument("--remote-ref", default=DEFAULT_REMOTE_REF)
    parser.add_argument("--cert", type=Path, help="tls-observer stage only")
    parser.add_argument("--key", type=Path, help="tls-observer stage only")
    parser.add_argument("--prefix", type=Path, help="tls-observer stage only")
    parser.add_argument("--proton-wine", type=Path, help="tls-observer stage only")
    parser.add_argument("--ca-thumbprint", help="tls-observer stage only")
    parser.add_argument("--allow-steam-running", action="store_true")
    args = parser.parse_args()
    result = run_preflight(
        stage=args.stage, upstream_ip=args.upstream_ip,
        pid_file=args.pid_file, ready_file=args.ready_file, log_path=args.log,
        expected_branch=args.expected_branch, expected_head=args.expected_head,
        expected_remote_tip=args.expected_remote_tip,
        expected_ahead=args.expected_ahead, expected_behind=args.expected_behind,
        expected_parent=args.expected_parent, remote_ref=args.remote_ref,
        scratch_path=args.scratch, cert_path=args.cert, key_path=args.key,
        prefix=args.prefix, proton_wine=args.proton_wine,
        ca_thumbprint=args.ca_thumbprint,
        require_steam_closed=not args.allow_steam_running,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
