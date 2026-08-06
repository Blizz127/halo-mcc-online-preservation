"""Bounded TLS/ALPN observer that never forwards traffic or persists values/bodies.

Runtime bounds are derived from measured live launch behaviour, not from the
synthetic defaults this tool started with. Every run records why it ended, so a
run that expired before the client arrived can never be mistaken for a run that
proved the client never came.
"""

from __future__ import annotations

import argparse
import datetime
import errno
import ipaddress
import json
import math
import os
import socket
import ssl
import stat
import sys
import threading
import time
import uuid
from pathlib import Path

from cryptography import x509

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exclusions import safe_header_names  # noqa: E402
import prelaunch_relay  # noqa: E402
import schema_extract  # noqa: E402

ALPN_PROTOCOLS = ["h2", "http/1.1"]
MAX_CONNECTIONS = 8
# One hard runtime bound across the live interception tools. This was 120s, a
# synthetic-era value that was never reconciled with the live launch timeline,
# and it is raised to the relay's already-accepted maximum rather than to a new
# number invented here. A longer experiment still needs a new rung.
MAX_SECONDS = prelaunch_relay.MAX_SECONDS
TLS_TOOL = "tls-observer"
LOG_FORMAT = "p0c2d1r0-tls-observer-v2"
LAUNCH_GATE_FORMAT = "p0c2d1r1-launch-window-v1"
BASELINE_FORMAT = "p0c2d1r1-direct-baseline-v1"
BASELINE_DECISION_FORMAT = "p0c2d1r1-direct-baseline-decision-v1"

# Live bounds, derived from measured launch behaviour rather than guessed.
#
# The observer must already be listening before the redirect is installed, so
# its runtime has to cover the redirect install and scope verification *and*
# everything the relay's window had to cover:
#
#     redirect install + scope verify + Steam start + Play to title services
#
# Two measurements bound that. P0-C1 (`E-P0C1-003`) recorded title-service
# resolution at +72s after MCC launch. P0-C2D (`E-P0C2D-004`) recorded 75s from
# redirect scope verification to the settings connection arriving at the local
# listener -- and the observer's clock starts before that verification, not
# after it.
OBSERVED_LAUNCH_TO_TITLE_SERVICE_SECONDS = 72.0
OBSERVED_REDIRECT_VERIFY_TO_CONNECT_SECONDS = 75.0
RECOMMENDED_LIVE_SECONDS = 240.0
# A client launch is allowed only while the observer still has enough runtime
# for twice the measured redirect-verify-to-connect interval. This preserves a
# full measured 75-second arrival window plus 75 seconds of operational margin,
# while remaining compatible with the recommended 240-second observer run.
MIN_LIVE_LAUNCH_REMAINING_SECONDS = 150.0
# Reconnect headroom. Unlike the relay, the observer has no lingering mode: it
# stops accepting once the cap is reached. A cap of 1 would therefore leave an
# installed redirect pointing at an exited listener after the first connection,
# and MCC's retry -- the very behaviour that distinguishes a rejected
# certificate from an accepted one -- would meet a refused connection instead
# of the observer.
RECOMMENDED_LIVE_MAX_CONNECTIONS = 8


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def _finite_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    converted = float(value)
    return converted if math.isfinite(converted) else None


def _listener_owned_by_pid(pid: int, bind: str, port: int) -> bool:
    """Return whether PID owns the exact IPv4 LISTEN socket, without connecting."""
    if pid <= 0 or not 1 <= port <= 65535:
        return False
    try:
        address_hex = socket.inet_aton(bind)[::-1].hex().upper()
        endpoint = f"{address_hex}:{port:04X}"
        inodes: set[str] = set()
        with Path("/proc/net/tcp").open(encoding="ascii") as table:
            next(table, None)
            for line in table:
                fields = line.split()
                if len(fields) >= 10 and fields[1] == endpoint and fields[3] == "0A":
                    inodes.add(fields[9])
        if not inodes:
            return False
        for descriptor in Path(f"/proc/{pid}/fd").iterdir():
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in inodes:
                return True
    except (OSError, ValueError):
        return False
    return False


def _empty_launch_gate_result(minimum_required: float) -> dict:
    return {
        "format": LAUNCH_GATE_FORMAT,
        "observer_alive": False,
        "listener_ready": False,
        "run_identity_valid": False,
        "runtime_metadata_valid": False,
        "configured_timeout_seconds": None,
        "elapsed_seconds": None,
        "remaining_seconds": None,
        "minimum_required_seconds": minimum_required,
        "safe_to_launch": False,
        "failure_reasons": ["malformed_control_state"],
    }


def evaluate_launch_window(
    pid_file: Path,
    ready_file: Path,
    bind: str = prelaunch_relay.AUTHORIZED_BIND,
    port: int = prelaunch_relay.AUTHORIZED_PORT,
    minimum_required: float = MIN_LIVE_LAUNCH_REMAINING_SECONDS,
    *,
    monotonic_now=time.monotonic,
    pid_matches=prelaunch_relay._pid_matches_tool,
    listener_owned=_listener_owned_by_pid,
) -> dict:
    """Evaluate the owned observer launch window and return sanitized metadata."""
    minimum = _finite_number(minimum_required)
    if minimum is None or minimum <= 0:
        minimum = MIN_LIVE_LAUNCH_REMAINING_SECONDS
    result = _empty_launch_gate_result(minimum)
    try:
        pid_identity, pid_state = prelaunch_relay._read_control_identity(Path(pid_file))
        ready_identity, ready_state = prelaunch_relay._read_control_identity(Path(ready_file))
        if not isinstance(pid_state, dict) or not isinstance(ready_state, dict):
            return result

        pid = pid_state.get("pid")
        run_id = pid_state.get("run_id")
        common_identity = (
            pid_state.get("format") == prelaunch_relay.CONTROL_FORMAT
            and ready_state.get("format") == prelaunch_relay.CONTROL_FORMAT
            and pid_state.get("tool") == TLS_TOOL
            and ready_state.get("tool") == TLS_TOOL
            and pid_state.get("kind") == "pid"
            and ready_state.get("kind") == "ready"
            and isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
            and ready_state.get("pid") == pid
            and isinstance(run_id, str) and bool(run_id)
            and ready_state.get("run_id") == run_id
            and ready_state.get("ready") is True
            and ready_state.get("bind") == bind
            and ready_state.get("port") == port
        )

        start_pid = _finite_number(pid_state.get("run_started_monotonic_seconds"))
        start_ready = _finite_number(ready_state.get("run_started_monotonic_seconds"))
        timeout_pid = _finite_number(pid_state.get("configured_timeout_seconds"))
        timeout_ready = _finite_number(ready_state.get("configured_timeout_seconds"))
        deadline_pid = _finite_number(pid_state.get("deadline_monotonic_seconds"))
        deadline_ready = _finite_number(ready_state.get("deadline_monotonic_seconds"))
        wall_pid = pid_state.get("run_started_wall_time")
        wall_ready = ready_state.get("run_started_wall_time")
        try:
            parsed_wall = datetime.datetime.fromisoformat(wall_pid) if isinstance(wall_pid, str) else None
        except ValueError:
            parsed_wall = None
        metadata_valid = (
            start_pid is not None and start_ready == start_pid
            and timeout_pid is not None and timeout_ready == timeout_pid
            and deadline_pid is not None and deadline_ready == deadline_pid
            and 0 < timeout_pid <= MAX_SECONDS
            and math.isclose(
                deadline_pid, start_pid + timeout_pid, rel_tol=0.0, abs_tol=1e-6
            )
            and wall_ready == wall_pid
            and parsed_wall is not None and parsed_wall.tzinfo is not None
        )
        now = _finite_number(monotonic_now())
        if not common_identity or not metadata_valid or now is None or now < start_pid:
            return result

        observer_alive = bool(pid_matches(pid, TLS_TOOL))
        listener_ready = bool(listener_owned(pid, bind, port))

        # Re-read after process/listener inspection so replaced controls cannot
        # pass on identities that ceased to be owned during the check.
        pid_after, _ = prelaunch_relay._read_control_identity(Path(pid_file))
        ready_after, _ = prelaunch_relay._read_control_identity(Path(ready_file))
        controls_stable = (
            pid_after.device == pid_identity.device
            and pid_after.inode == pid_identity.inode
            and pid_after.content == pid_identity.content
            and ready_after.device == ready_identity.device
            and ready_after.inode == ready_identity.inode
            and ready_after.content == ready_identity.content
        )
        elapsed = now - start_pid
        remaining = deadline_pid - now
        reasons: list[str] = []
        if not controls_stable:
            reasons.append("run_identity_invalid")
        if not observer_alive:
            reasons.append("observer_not_alive")
        if not listener_ready:
            reasons.append("listener_not_ready")
        if remaining <= 0:
            reasons.append("observer_expired")
        elif remaining < minimum:
            reasons.append("insufficient_remaining_runtime")

        result.update({
            "observer_alive": observer_alive,
            "listener_ready": listener_ready,
            "run_identity_valid": controls_stable,
            "runtime_metadata_valid": True,
            "configured_timeout_seconds": timeout_pid,
            "elapsed_seconds": round(elapsed, 3),
            "remaining_seconds": round(remaining, 3),
            "safe_to_launch": not reasons,
            "failure_reasons": reasons,
        })
        return result
    except (OSError, prelaunch_relay.RelaySafetyError, TypeError, ValueError):
        return result


def evaluate_baseline(document: object) -> dict:
    """Validate and decide the machine-recorded direct-baseline contract."""
    required_booleans = (
        "steam_launched_normally",
        "mcc_launched_normally",
        "identity_success",
        "main_menu_success",
        "certificate_or_service_error",
        "clean_shutdown",
    )
    output = {
        "format": BASELINE_DECISION_FORMAT,
        "contract_valid": False,
        "steam_launched_normally": None,
        "mcc_launched_normally": None,
        "sign_in_mode": None,
        "identity_success": None,
        "main_menu_success": None,
        "certificate_or_service_error": None,
        "clean_shutdown": None,
        "safe_to_continue": False,
        "failure_reasons": ["malformed_baseline"],
    }
    if not isinstance(document, dict) or document.get("format") != BASELINE_FORMAT:
        return output
    if any(type(document.get(name)) is not bool for name in required_booleans):
        return output
    sign_in_mode = document.get("sign_in_mode")
    if sign_in_mode not in {"cached", "interactive", "unknown"}:
        return output

    output.update({name: document[name] for name in required_booleans})
    output["sign_in_mode"] = sign_in_mode
    output["contract_valid"] = True
    reasons: list[str] = []
    if not document["steam_launched_normally"]:
        reasons.append("steam_launch_failed")
    if not document["mcc_launched_normally"]:
        reasons.append("mcc_launch_failed")
    if not document["identity_success"]:
        reasons.append("identity_not_confirmed")
    if not document["main_menu_success"]:
        reasons.append("main_menu_not_confirmed")
    if document["certificate_or_service_error"]:
        reasons.append("certificate_or_service_error")
    if not document["clean_shutdown"]:
        reasons.append("unclean_shutdown")
    output["failure_reasons"] = reasons
    output["safe_to_continue"] = not reasons
    return output


def _read_bounded_json(path: Path) -> object:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError("cannot safely inspect baseline record") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise ValueError("baseline record is not a bounded regular file")
        content = os.read(fd, 4097)
    finally:
        os.close(fd)
    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("baseline record is malformed") from exc


def run_observer(certfile: Path, keyfile: Path, port: int = 8443, bind: str = "127.0.0.1",
                 mode: str = "stage_d", max_connections: int = 1,
                 log_path: Path | None = None, ready_event: threading.Event | None = None,
                 total_timeout: float = 30.0, pid_file: Path | None = None,
                 ready_file: Path | None = None, enforce_production: bool = False,
                 required_sni: str | None = None) -> list[dict]:
    if not 1 <= max_connections <= MAX_CONNECTIONS:
        raise ValueError(f"max_connections must be 1..{MAX_CONNECTIONS}")
    if mode != "stage_d":
        raise ValueError("observer supports only the non-forwarding stage_d mode")
    if not 0 < total_timeout <= MAX_SECONDS:
        raise ValueError(f"total_timeout must be >0 and <= {MAX_SECONDS:g}")
    if enforce_production:
        if bind != prelaunch_relay.AUTHORIZED_BIND or port != prelaunch_relay.AUTHORIZED_PORT:
            raise ValueError("production observer must bind exactly 127.0.0.77:443")
        cert_path, key_path = Path(certfile), Path(keyfile)
        if (
            not cert_path.is_file()
            or not key_path.is_file()
            or not prelaunch_relay._outside_repository(cert_path)
            or not prelaunch_relay._outside_repository(key_path)
            or prelaunch_relay._path_has_symlink(cert_path)
            or prelaunch_relay._path_has_symlink(key_path)
            or (key_path.stat().st_mode & 0o777) != 0o600
        ):
            raise ValueError("production certificate/key paths failed the safe-output contract")
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns_names = sans.get_values_for_type(x509.DNSName)
            lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
            now = datetime.datetime.now(datetime.UTC)
        except (OSError, ValueError, x509.ExtensionNotFound) as exc:
            raise ValueError("production certificate could not be validated") from exc
        if (
            dns_names != [prelaunch_relay.AUTHORIZED_HOST]
            or lifetime > datetime.timedelta(days=2)
            or not cert.not_valid_before_utc <= now < cert.not_valid_after_utc
        ):
            raise ValueError("production certificate violates the exact-host/validity contract")
        required_sni = prelaunch_relay.AUTHORIZED_HOST
    elif not ipaddress.ip_address(bind).is_loopback or port < 1024:
        raise ValueError("synthetic observer must use loopback and a high port")
    control_paths = {Path(path) for path in (pid_file, ready_file) if path is not None}
    prelaunch_relay._validate_runtime_paths(
        [log_path, pid_file, ready_file], require_outside_repository=enforce_production,
        allow_existing=control_paths,
    )
    prelaunch_relay.prepare_control_path(pid_file, TLS_TOOL, "pid")
    prelaunch_relay.prepare_control_path(ready_file, TLS_TOOL, "ready")

    observations: list[dict] = []
    exit_reason = "total_deadline"
    started_monotonic = time.monotonic()
    started_wall_time = _now()
    deadline = started_monotonic + total_timeout

    def _document() -> dict:
        """Metadata-only run summary. No payload, peer address, or value appears here."""
        return {
            "format": LOG_FORMAT,
            "observation_count": len(observations),
            "exit_reason": exit_reason,
            "total_timeout_seconds": total_timeout,
            "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
            "observations": observations,
        }

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    context.set_alpn_protocols(ALPN_PROTOCOLS)
    seen_sni: dict[int, str | None] = {}
    last_sni: list[str | None] = [None]

    def sni_callback(tls_socket, server_name, _context):
        seen_sni[id(tls_socket)] = server_name
        last_sni[0] = server_name

    context.sni_callback = sni_callback
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind, port))
        listener.listen(min(max_connections, 8))
        listener.settimeout(0.25)
    except OSError as exc:
        listener.close()
        if exc.errno == errno.EADDRINUSE:
            raise ValueError(f"listen address already in use: {bind}:{port}") from exc
        raise ValueError(f"listener setup failed for {bind}:{port}: {exc.strerror}") from exc
    safe_log = None
    try:
        safe_log = prelaunch_relay.SafeJsonLog(log_path)
        safe_log.write(_document())
    except BaseException:
        if safe_log is not None:
            safe_log.close()
        listener.close()
        raise
    assert safe_log is not None
    pid = os.getpid()
    run_id = uuid.uuid4().hex
    runtime_identity = {
        "run_started_monotonic_seconds": started_monotonic,
        "run_started_wall_time": started_wall_time,
        "configured_timeout_seconds": total_timeout,
        "deadline_monotonic_seconds": deadline,
    }
    pid_identity = None
    ready_identity = None
    try:
        pid_identity = prelaunch_relay.create_control_file(
            pid_file, TLS_TOOL, "pid", pid, run_id, runtime_identity
        )
        ready_identity = prelaunch_relay.create_control_file(
            ready_file, TLS_TOOL, "ready", pid, run_id,
            {**runtime_identity, "ready": True, "bind": bind, "port": port},
        )
        if ready_event:
            ready_event.set()
        while len(observations) < max_connections and time.monotonic() < deadline:
            try:
                raw, _peer = listener.accept()
            except TimeoutError:
                continue
            last_sni[0] = None
            record = {
                "timestamp": _now(), "sni": None, "tls_completed": False,
                "tls_version": None, "cipher": None, "alpn": None, "alert_class": None,
                "sni_result": None, "protocol_result": None,
                "certificate_verdict": "unknown_no_application_data",
                "client_sent_application_data": False, "request_method": None,
                "normalized_path": None, "query_parameter_names": [],
                "request_header_names": [],
            }
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("observer total deadline reached before TLS handshake")
                raw.settimeout(min(10.0, remaining))
                tls = context.wrap_socket(raw, server_side=True)
                record["sni"] = schema_extract.normalize_hostname(seen_sni.get(id(tls)))
                record["tls_completed"] = True
                record["tls_version"] = tls.version()
                cipher = tls.cipher()
                record["cipher"] = cipher[0] if cipher else None
                record["alpn"] = tls.selected_alpn_protocol()
                if required_sni is None:
                    record["sni_result"] = "not_enforced_synthetic"
                elif record["sni"] is None:
                    record["sni_result"] = "missing"
                    record["protocol_result"] = "sni_rejected"
                elif record["sni"] != required_sni:
                    record["sni_result"] = "mismatch"
                    record["protocol_result"] = "sni_rejected"
                else:
                    record["sni_result"] = "exact"

                if record["protocol_result"] == "sni_rejected":
                    pass  # Close without reading application data.
                elif record["alpn"] == "h2":
                    record["protocol_result"] = "unsupported_protocol"
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        tls.settimeout(min(1.0, remaining))
                        opaque_presence = tls.recv(1)
                        if opaque_presence:
                            record["client_sent_application_data"] = True
                            record["certificate_verdict"] = "accepted_certificate"
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("observer total deadline reached before application data")
                    tls.settimeout(min(10.0, remaining))
                    data = tls.recv(16384)
                    if data:
                        record["client_sent_application_data"] = True
                        record["certificate_verdict"] = "accepted_certificate"
                        record["protocol_result"] = "http1_metadata"
                    else:
                        record["protocol_result"] = "no_application_data"
                    if data and record["alpn"] in (None, "http/1.1"):
                        head = data.split(b"\r\n\r\n", 1)[0]
                        lines = head.decode("latin-1").splitlines()
                        bits = lines[0].split() if lines else []
                        if len(bits) >= 2:
                            record["request_method"] = schema_extract.normalize_http_method(bits[0])
                            record.update(schema_extract.normalize_request_target(bits[1]))
                        record["request_header_names"] = safe_header_names(
                            line.split(":", 1)[0] for line in lines[1:] if ":" in line
                        )
                tls.close()
            except ssl.SSLError as exc:
                record["alert_class"] = str(getattr(exc, "reason", type(exc).__name__))
                if record["sni"] is None:
                    record["sni"] = schema_extract.normalize_hostname(last_sni[0])
                if required_sni is not None:
                    if record["sni"] is None:
                        record["sni_result"] = "missing"
                        record["protocol_result"] = "sni_rejected"
                    elif record["sni"] != required_sni:
                        record["sni_result"] = "mismatch"
                        record["protocol_result"] = "sni_rejected"
                record["certificate_verdict"] = (
                    "rejected_after_server_handshake"
                    if record["tls_completed"]
                    else "rejected_during_handshake"
                )
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                record["alert_class"] = type(exc).__name__
            finally:
                observations.append(record)
                try:
                    if log_path:
                        safe_log.write(_document())
                finally:
                    raw.close()
        # Recorded so a cap-bounded run is never read as a complete one: the
        # observer stops accepting at the cap, and a `D. OBSERVER NOT CONTACTED`
        # reading is only sound when the run actually reached its deadline.
        if len(observations) >= max_connections:
            exit_reason = "connection_cap_reached"
    finally:
        if log_path:
            try:
                safe_log.write(_document())
            except OSError:
                pass
        listener.close()
        prelaunch_relay.remove_owned_control(ready_identity)
        prelaunch_relay.remove_owned_control(pid_identity)
        safe_log.close()
    return observations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-launch-window", action="store_true")
    modes.add_argument("--check-baseline", type=Path)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--bind", default=prelaunch_relay.AUTHORIZED_BIND)
    parser.add_argument("--max-connections", type=int,
                        default=RECOMMENDED_LIVE_MAX_CONNECTIONS,
                        help="reconnect headroom; the observer stops accepting at the cap")
    parser.add_argument("--seconds", type=float, default=RECOMMENDED_LIVE_SECONDS,
                        help=f"total runtime; hard maximum is {MAX_SECONDS:g}s")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--pid-file", type=Path)
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args()
    if args.check_launch_window:
        if args.pid_file is None or args.ready_file is None:
            parser.error("--check-launch-window requires --pid-file and --ready-file")
        if (
            args.bind != prelaunch_relay.AUTHORIZED_BIND
            or args.port != prelaunch_relay.AUTHORIZED_PORT
        ):
            decision = _empty_launch_gate_result(
                MIN_LIVE_LAUNCH_REMAINING_SECONDS
            )
            decision["failure_reasons"] = ["unauthorized_listener_target"]
        else:
            decision = evaluate_launch_window(
                args.pid_file, args.ready_file, args.bind, args.port
            )
        print(json.dumps(decision, sort_keys=True))
        return 0 if decision["safe_to_launch"] else 2
    if args.check_baseline is not None:
        try:
            baseline = _read_bounded_json(args.check_baseline)
        except ValueError:
            baseline = None
        decision = evaluate_baseline(baseline)
        print(json.dumps(decision, sort_keys=True))
        return 0 if decision["safe_to_continue"] else 2
    if any(value is None for value in (args.cert, args.key, args.log, args.pid_file, args.ready_file)):
        parser.error("observer mode requires --cert, --key, --log, --pid-file, and --ready-file")
    result = run_observer(args.cert, args.key, args.port, args.bind, "stage_d",
                          args.max_connections, args.log, total_timeout=args.seconds,
                          pid_file=args.pid_file, ready_file=args.ready_file,
                          enforce_production=True)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
