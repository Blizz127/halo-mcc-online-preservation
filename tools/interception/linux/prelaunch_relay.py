"""Bounded blind relay for the P0-C2D pre-launch settings probe.

The command-line path is intentionally production-specific: it may bind only
127.0.0.77, targets exactly settings.svc.halowaypoint.com, accepts a numeric
upstream IPv4 address, and forwards port 443 without DNS or TLS termination.
Tests call ``serve(..., enforce_production=False)`` with loopback/high ports.
Only timestamps, directional byte counts, duration, and an error class are
persisted. Payload bytes and peer addresses are never logged.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import select
import socket
import stat
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

AUTHORIZED_BIND = "127.0.0.77"
AUTHORIZED_HOST = "settings.svc.halowaypoint.com"
AUTHORIZED_PORT = 443
DEFAULT_MAX_CONNECTIONS = 4
DEFAULT_SECONDS = 120.0
DEFAULT_IDLE_SECONDS = 30.0
MAX_SECONDS = 300.0
MAX_CONNECTIONS = 16
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_LOG_LOCK = threading.Lock()
CONTROL_FORMAT = "p0c2d0-control-v1"
RELAY_TOOL = "prelaunch-relay"


class RelaySafetyError(ValueError):
    pass


def _now() -> float:
    return time.time()


def _path_has_symlink(path: Path) -> bool:
    """Check every existing component without resolving symlinks away."""
    absolute = Path(path).absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            return True
    return False


def _outside_repository(path: Path) -> bool:
    try:
        Path(path).resolve(strict=False).relative_to(REPOSITORY_ROOT)
    except ValueError:
        return True
    return False


def _validate_runtime_paths(paths: list[Path | None], require_outside_repository: bool,
                            allow_existing: set[Path]) -> None:
    selected = [Path(path) for path in paths if path is not None]
    resolved = [path.resolve(strict=False) for path in selected]
    if len(set(resolved)) != len(resolved):
        raise RelaySafetyError("log, PID, and ready paths must be distinct")
    for path in selected:
        if (path.exists() or path.is_symlink()) and path not in allow_existing:
            raise RelaySafetyError(f"refusing existing runtime path: {path}")
        if not path.parent.is_dir():
            raise RelaySafetyError(f"runtime path parent does not exist: {path.parent}")
        if not os.access(path.parent, os.W_OK | os.X_OK):
            raise RelaySafetyError(f"runtime path parent is not writable: {path.parent}")
        if _path_has_symlink(path.parent):
            raise RelaySafetyError(f"runtime path may not traverse a symlink: {path}")
        if require_outside_repository and not _outside_repository(path):
            raise RelaySafetyError(f"production runtime path must be outside repository: {path}")


def validate_runtime_paths(paths: list[Path | None], require_outside_repository: bool) -> None:
    _validate_runtime_paths(paths, require_outside_repository, set())


def validate_production_contract(bind: str, target_host: str, upstream_ip: str,
                                 upstream_port: int) -> ipaddress.IPv4Address:
    if bind != AUTHORIZED_BIND:
        raise RelaySafetyError(f"bind must be exactly {AUTHORIZED_BIND}")
    if target_host != AUTHORIZED_HOST:
        raise RelaySafetyError(f"target host must be exactly {AUTHORIZED_HOST}")
    try:
        address = ipaddress.ip_address(upstream_ip)
    except ValueError as exc:
        raise RelaySafetyError("upstream must be a numeric IPv4 address; DNS is forbidden") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise RelaySafetyError("production upstream must be a global unicast IPv4 address")
    if upstream_port != AUTHORIZED_PORT:
        raise RelaySafetyError("production upstream port must be 443")
    return address


def validate_bounds(max_connections: int, total_timeout: float, idle_timeout: float) -> None:
    if not 1 <= max_connections <= MAX_CONNECTIONS:
        raise RelaySafetyError(f"max_connections must be 1..{MAX_CONNECTIONS}")
    if not 0 < total_timeout <= MAX_SECONDS:
        raise RelaySafetyError(f"seconds must be >0 and <= {MAX_SECONDS:g}")
    if not 0 < idle_timeout <= total_timeout:
        raise RelaySafetyError("idle timeout must be >0 and no greater than total timeout")


@dataclass(frozen=True)
class ControlFileIdentity:
    path: Path
    device: int
    inode: int
    content: bytes


def _read_control_identity(path: Path) -> tuple[ControlFileIdentity, dict]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise RelaySafetyError(f"cannot safely inspect control path {path}: {exc.strerror}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise RelaySafetyError(f"control path is not a regular file: {path}")
        if before.st_size > 4096:
            raise RelaySafetyError(f"control path is too large to be ours: {path}")
        content = os.read(fd, 4097)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise RelaySafetyError(f"control path changed while inspected: {path}")
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RelaySafetyError(f"refusing unrelated file at control path: {path}") from exc
    return ControlFileIdentity(path, after.st_dev, after.st_ino, content), document


def _pid_matches_tool(pid: int, tool: str) -> bool:
    if pid <= 0:
        return False
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
            "utf-8", errors="replace"
        )
    except OSError:
        return False
    expected = "prelaunch_relay.py" if tool == RELAY_TOOL else "tls_observer.py"
    return expected in command


def _unlink_matching(identity: ControlFileIdentity) -> bool:
    try:
        current, _document = _read_control_identity(identity.path)
    except FileNotFoundError:
        return False
    except RelaySafetyError:
        return False
    if (
        current.device != identity.device
        or current.inode != identity.inode
        or current.content != identity.content
    ):
        return False
    try:
        identity.path.unlink()
    except FileNotFoundError:
        return False
    return True


def _unlink_inode(path: Path, device: int, inode: int) -> bool:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(current.st_mode) or current.st_dev != device or current.st_ino != inode:
        return False
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


def prepare_control_path(path: Path | None, tool: str, kind: str) -> None:
    """Remove only a demonstrably stale control file belonging to this tool."""
    if path is None:
        return
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return
    identity, document = _read_control_identity(path)
    if (
        document.get("format") != CONTROL_FORMAT
        or document.get("tool") != tool
        or document.get("kind") != kind
        or not isinstance(document.get("pid"), int)
        or not isinstance(document.get("run_id"), str)
    ):
        raise RelaySafetyError(f"refusing unrelated file at control path: {path}")
    pid = document["pid"]
    if _pid_matches_tool(pid, tool):
        raise RelaySafetyError(f"active {tool} {kind} state exists for PID {pid}: {path}")
    if not _unlink_matching(identity):
        raise RelaySafetyError(f"stale control path changed before removal: {path}")


def create_control_file(path: Path | None, tool: str, kind: str, pid: int,
                        run_id: str, extra: dict | None = None) -> ControlFileIdentity | None:
    if path is None:
        return None
    path = Path(path)
    document = {
        "format": CONTROL_FORMAT,
        "tool": tool,
        "kind": kind,
        "pid": pid,
        "run_id": run_id,
    }
    if extra:
        document.update(extra)
    content = (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{run_id}.{kind}.tmp")
    try:
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
    except OSError as exc:
        raise RelaySafetyError(f"cannot create atomic {kind} staging file: {exc.strerror}") from exc
    created = os.fstat(fd)
    info = None
    try:
        pending = memoryview(content)
        while pending:
            written = os.write(fd, pending)
            if written <= 0:
                raise RelaySafetyError(f"cannot complete atomic {kind} file write: {path}")
            pending = pending[written:]
        os.fsync(fd)
        info = os.fstat(fd)
    except BaseException:
        os.close(fd)
        _unlink_inode(temporary, created.st_dev, created.st_ino)
        raise
    else:
        os.close(fd)
    assert info is not None
    staged = ControlFileIdentity(temporary, info.st_dev, info.st_ino, content)
    try:
        os.link(temporary, path, follow_symlinks=False)
    except OSError as exc:
        remove_owned_control(staged)
        raise RelaySafetyError(f"cannot atomically publish {kind} file {path}: {exc.strerror}") from exc
    if not remove_owned_control(staged):
        # The published hard link remains valid; a replaced staging pathname is
        # preserved rather than blindly removed.
        pass
    return ControlFileIdentity(path, info.st_dev, info.st_ino, content)


def remove_owned_control(identity: ControlFileIdentity | None) -> bool:
    return False if identity is None else _unlink_matching(identity)


class SafeJsonLog:
    """Exclusive, inode-stable JSON output that never follows a replaced pathname."""

    def __init__(self, log_path: Path | None):
        self.path = Path(log_path) if log_path else None
        self._log = None
        if self.path:
            fd = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            self._log = os.fdopen(fd, "w", encoding="utf-8")

    def write(self, document: dict) -> None:
        if self._log is None:
            return
        self._log.seek(0)
        self._log.truncate()
        json.dump(document, self._log, indent=2)
        self._log.write("\n")
        self._log.flush()

    def close(self) -> None:
        if self._log is not None:
            self._log.close()
            self._log = None


class RelayState:
    def __init__(self, log_path: Path | None):
        self.log_path = Path(log_path) if log_path else None
        self.connections: list[dict] = []
        self.failure_class: str | None = None
        self._safe_log = SafeJsonLog(self.log_path)
        self._persist()

    def _persist(self) -> None:
        self._safe_log.write({
            "format": "p0c2d0-safe-relay-v1",
            "connection_count": len(self.connections),
            "connections": self.connections,
        })

    def record(self, entry: dict) -> None:
        with _LOG_LOCK:
            self.connections.append(entry)
            try:
                self._persist()
            except OSError as exc:
                self.failure_class = type(exc).__name__

    def close(self) -> None:
        self._safe_log.close()


def _pump(state: RelayState, client: socket.socket, upstream_address: tuple[str, int],
          idle_timeout: float, deadline: float, stop_event: threading.Event) -> None:
    opened = _now()
    opened_monotonic = time.monotonic()
    entry = {
        "opened": opened,
        "bytes_client_to_upstream": 0,
        "bytes_upstream_to_client": 0,
        "closed": None,
        "duration_s": None,
        "error_class": None,
    }
    upstream: socket.socket | None = None
    open_sides: set[socket.socket] = set()
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            entry["error_class"] = "TotalTimeout"
            return
        upstream = socket.create_connection(
            upstream_address, timeout=min(15.0, idle_timeout, remaining)
        )
        open_sides = {client, upstream}
        while open_sides and not stop_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                entry["error_class"] = "TotalTimeout"
                break
            operation_timeout = min(idle_timeout, remaining)
            client.settimeout(operation_timeout)
            upstream.settimeout(operation_timeout)
            readable, _, errored = select.select(
                list(open_sides), [], list(open_sides), operation_timeout
            )
            if errored:
                entry["error_class"] = (
                    "TotalTimeout" if time.monotonic() >= deadline
                    else "ServerShutdown" if stop_event.is_set()
                    else "SocketError"
                )
                break
            if not readable:
                entry["error_class"] = (
                    "TotalTimeout" if time.monotonic() >= deadline else "IdleTimeout"
                )
                break
            for source in readable:
                destination = upstream if source is client else client
                try:
                    data = source.recv(65536)
                except (ConnectionResetError, TimeoutError, OSError) as exc:
                    entry["error_class"] = (
                        "TotalTimeout" if time.monotonic() >= deadline
                        else "ServerShutdown" if stop_event.is_set()
                        else type(exc).__name__
                    )
                    open_sides.discard(source)
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                if not data:
                    open_sides.discard(source)
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                counter = (
                    "bytes_client_to_upstream"
                    if source is client
                    else "bytes_upstream_to_client"
                )
                pending = memoryview(data)
                while pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("total relay deadline reached while forwarding")
                    destination.settimeout(min(idle_timeout, remaining))
                    sent = destination.send(pending)
                    if sent == 0:
                        raise ConnectionResetError("zero-byte send")
                    entry[counter] += sent
                    pending = pending[sent:]
        if open_sides and entry["error_class"] is None:
            entry["error_class"] = (
                "TotalTimeout" if time.monotonic() >= deadline else "ServerShutdown"
            )
    except OSError as exc:
        entry["error_class"] = (
            "TotalTimeout" if time.monotonic() >= deadline
            else "ServerShutdown" if stop_event.is_set()
            else type(exc).__name__
        )
    finally:
        entry["closed"] = _now()
        entry["duration_s"] = round(time.monotonic() - opened_monotonic, 3)
        for stream in (client, upstream):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        state.record(entry)


def serve(bind: str, port: int, target_host: str, upstream_ip: str, upstream_port: int,
          log_path: Path | None, max_connections: int, total_timeout: float,
          idle_timeout: float, pid_file: Path | None = None, ready_file: Path | None = None,
          enforce_production: bool = True,
          ready_event: threading.Event | None = None) -> RelayState:
    validate_bounds(max_connections, total_timeout, idle_timeout)
    if enforce_production:
        validate_production_contract(bind, target_host, upstream_ip, upstream_port)
        if port != AUTHORIZED_PORT:
            raise RelaySafetyError("production listen port must be 443")
    else:
        if (
            not ipaddress.ip_address(bind).is_loopback
            or not ipaddress.ip_address(upstream_ip).is_loopback
        ):
            raise RelaySafetyError("synthetic mode is loopback-only")
        if port < 1024 or upstream_port < 1024:
            raise RelaySafetyError("synthetic mode requires high unprivileged ports")

    control_paths = {Path(path) for path in (pid_file, ready_file) if path is not None}
    _validate_runtime_paths(
        [log_path, pid_file, ready_file], require_outside_repository=enforce_production,
        allow_existing=control_paths,
    )
    prepare_control_path(pid_file, RELAY_TOOL, "pid")
    prepare_control_path(ready_file, RELAY_TOOL, "ready")
    stop_event = threading.Event()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind, port))
        listener.listen(min(max_connections, 16))
        listener.settimeout(0.25)
    except OSError as exc:
        listener.close()
        if exc.errno == errno.EADDRINUSE:
            raise RelaySafetyError(f"listen address already in use: {bind}:{port}") from exc
        raise RelaySafetyError(f"listener setup failed for {bind}:{port}: {exc.strerror}") from exc

    try:
        state = RelayState(log_path)
    except BaseException:
        listener.close()
        raise
    threads: list[threading.Thread] = []
    clients: list[socket.socket] = []
    deadline = time.monotonic() + total_timeout
    active_threads: list[threading.Thread] = []
    pid = os.getpid()
    run_id = uuid.uuid4().hex
    pid_identity: ControlFileIdentity | None = None
    ready_identity: ControlFileIdentity | None = None
    try:
        pid_identity = create_control_file(pid_file, RELAY_TOOL, "pid", pid, run_id)
        ready_identity = create_control_file(
            ready_file, RELAY_TOOL, "ready", pid, run_id,
            {"ready": True, "bind": bind, "port": port},
        )
        if ready_event:
            ready_event.set()
        while len(threads) < max_connections and time.monotonic() < deadline:
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            clients.append(client)
            thread = threading.Thread(
                target=_pump,
                args=(
                    state, client, (upstream_ip, upstream_port), idle_timeout, deadline, stop_event,
                ),
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
    finally:
        stop_event.set()
        listener.close()
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass
        shutdown_deadline = time.monotonic() + min(2.0, idle_timeout)
        for thread in threads:
            thread.join(timeout=max(0.0, shutdown_deadline - time.monotonic()))
        active_threads = [thread for thread in threads if thread.is_alive()]
        remove_owned_control(ready_identity)
        remove_owned_control(pid_identity)
        state.close()
    if active_threads:
        raise RelaySafetyError("relay worker exceeded the bounded shutdown deadline")
    if state.failure_class:
        raise RelaySafetyError(f"safe relay log failed: {state.failure_class}")
    return state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default=AUTHORIZED_BIND)
    parser.add_argument("--port", type=int, default=AUTHORIZED_PORT)
    parser.add_argument("--target-host", default=AUTHORIZED_HOST)
    parser.add_argument("--upstream-ip", required=True)
    parser.add_argument("--upstream-port", type=int, default=AUTHORIZED_PORT)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--pid-file", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--max-connections", type=int, default=DEFAULT_MAX_CONNECTIONS)
    parser.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    parser.add_argument("--idle-seconds", type=float, default=DEFAULT_IDLE_SECONDS)
    args = parser.parse_args()
    serve(args.bind, args.port, args.target_host, args.upstream_ip, args.upstream_port,
          args.log, args.max_connections, args.seconds, args.idle_seconds,
          args.pid_file, args.ready_file, enforce_production=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RelaySafetyError as exc:
        print(f"refusing: {exc}", file=sys.stderr)
        raise SystemExit(2)
